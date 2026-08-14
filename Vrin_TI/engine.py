"""Vrin_TI orchestration: ingestion → scoring → storage → SOC correlation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4
import asyncio

from .collectors.base import CollectedItem
from .collectors.feed_manager import FeedManager
from .config import TIConfig, config as default_config
from .connection_monitor import ConnectionMonitor
from .core.intelligence_bus import TransportManager
from .correlation import EventCorrelator, RelationshipEngine, ThreatCorrelator
from .database import ThreatDatabase
from .enrichment import EnrichmentManager
from .graph import SQLiteThreatGraph
from .logging_config import configure_logging
from .metrics import metrics
from .models import (
    AIConclusion, AssetReference, EventType, IndicatorReference,
    IntelligenceEvent, Lifecycle, Sighting, ThreatIndicator, utcnow,
)
from .normalization import canonical_type, detect_type, normalize_indicator
from .privacy import PrivacyGate
from .scoring.threat_score import calculate_threat_score
from .security import ReplayGuard, SecurityError
from .stix import STIXAdapter


class ThreatIntelligenceEngine:
    def __init__(self, config: TIConfig = default_config, database: Optional[ThreatDatabase] = None):
        self.config = config
        self.database = database or ThreatDatabase(config.database_path)
        self.logger = configure_logging(config.log_dir)
        self.bus = TransportManager(config, self.database)
        self.stix = STIXAdapter(self.database)
        self.privacy = PrivacyGate(config.external_enrichment, config.external_submission)
        self.enrichment = EnrichmentManager(self.database, self.privacy)
        self.event_correlator = EventCorrelator(self.database)
        self.threat_correlator = ThreatCorrelator(self.database)
        self.relationships = RelationshipEngine(self.database)
        self.graph = SQLiteThreatGraph(self.relationships)
        self.replay = ReplayGuard(config.replay_window_seconds)
        self.feeds = FeedManager(config, self.database, self)
        self.monitor = ConnectionMonitor(config, self.database, self.bus, self.feeds)
        self.started = False
        self.started_at: Optional[datetime] = None
        self.last_soc_event: Optional[datetime] = None
        self.last_ti_event: Optional[datetime] = None
        self._inbound_task: Optional[asyncio.Task] = None
        self._transport_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self.started:
            return
        await self.bus.connect()
        await self.feeds.start()
        self.started = True
        self.started_at = utcnow()
        self._inbound_task = asyncio.create_task(self._consume_inbound_queue(), name="ti-inbound-queue")
        self._transport_task = asyncio.create_task(self._monitor_transport(), name="ti-transport-monitor")
        self.logger.info("threat intelligence engine started", extra={"outcome": "success"})

    async def stop(self) -> None:
        if not self.started:
            return
        await self.feeds.stop()
        background = [task for task in (self._inbound_task, self._transport_task) if task]
        for task in background:
            task.cancel()
        if background:
            await asyncio.gather(*background, return_exceptions=True)
        self._inbound_task = None
        self._transport_task = None
        await self.bus.close()
        self.started = False
        self.logger.info("threat intelligence engine stopped", extra={"outcome": "success"})

    async def _monitor_transport(self) -> None:
        """Reconnect in bounded exponential bursts, with a cooldown between bursts."""
        delay = 5
        attempts = 0
        while True:
            await asyncio.sleep(delay)
            if self.bus.active is not self.bus.fallback:
                await self._flush_outbound_queue()
                delay, attempts = 30, 0
                continue
            if self.config.transport in {"local", "local_queue"}:
                delay, attempts = 30, 0
                continue
            await self.bus.connect()
            if self.bus.active is not self.bus.fallback:
                await self._flush_outbound_queue()
                delay, attempts = 30, 0
                continue
            attempts += 1
            delay = min(300, 5 * (2 ** min(attempts, 6)))
            if attempts >= 6:
                # End this retry burst instead of a tight infinite reconnect
                # loop; retry after a five-minute operational cooldown.
                attempts, delay = 0, 300

    async def _flush_outbound_queue(self) -> None:
        """Replay durable TI→SOC events after transport recovery."""
        if self.bus.active is self.bus.fallback:
            return
        for row in await asyncio.to_thread(self.database.dequeue, 100, "outbound"):
            try:
                event = IntelligenceEvent.model_validate(row["payload"])
                await self.bus.active.publish(event)
                await asyncio.to_thread(self.database.acknowledge_queue, row["queue_id"])
            except Exception as exc:
                delay = min(3600, 2 ** min(int(row.get("attempts", 0)), 10))
                await asyncio.to_thread(self.database.fail_queue, row["queue_id"], str(exc), delay)
                # One failure probably means the recovered transport is down;
                # stop this bounded flush and let the next monitor cycle retry.
                break

    async def _consume_inbound_queue(self) -> None:
        """Drain SOC events queued while TI/Redis/HTTP was unavailable."""
        while True:
            rows = await asyncio.to_thread(self.database.dequeue, 100, "inbound")
            if not rows:
                await asyncio.sleep(1)
                continue
            for row in rows:
                try:
                    event = IntelligenceEvent.model_validate(row["payload"])
                    await self.process_soc_event(event, enforce_replay=True)
                    await asyncio.to_thread(self.database.acknowledge_queue, row["queue_id"])
                except SecurityError as exc:
                    # Duplicate/replayed messages are terminal and acknowledged;
                    # transient validation/DB errors remain retryable.
                    await asyncio.to_thread(self.database.acknowledge_queue, row["queue_id"])
                    self.logger.warning("discarded replayed inbound event: %s", exc)
                except Exception as exc:
                    delay = min(3600, 2 ** min(int(row.get("attempts", 0)), 10))
                    await asyncio.to_thread(self.database.fail_queue, row["queue_id"], str(exc), delay)

    @staticmethod
    def _parse_time(value: Any) -> datetime:
        if value is None:
            return utcnow()
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return utcnow()

    def _score(self, indicator: ThreatIndicator, independent_sources: int = 1, sightings: int = 0, vulnerability: Optional[Dict[str, Any]] = None):
        vulnerability = vulnerability or {}
        return calculate_threat_score(
            source_reliabilities=[indicator.source_reliability], reported_confidence=indicator.confidence,
            independent_sources=independent_sources, last_seen=indicator.last_seen, sightings=sightings,
            malware_association=bool(indicator.malware_family), campaign_association=bool(indicator.campaign),
            attack_relevance=min(1.0, len(indicator.mitre_attack_ids) * 0.25),
            kev=bool(vulnerability.get("kev")), cvss=vulnerability.get("cvss"),
            false_positive_probability=indicator.false_positive_probability,
            observed_exploitation=bool(vulnerability.get("observed_exploitation")),
        )

    async def ingest_indicator(self, indicator: ThreatIndicator, publish: bool = True) -> Dict[str, Any]:
        kind = canonical_type(indicator.indicator_type).value
        indicator.indicator_type = kind
        indicator.normalized_value = normalize_indicator(kind, indicator.indicator_value)
        if indicator.ttl and not indicator.expires_at:
            from datetime import timedelta
            indicator.expires_at = indicator.last_seen + timedelta(seconds=indicator.ttl)
        vulnerability = None
        if kind == "cve":
            vulnerability = next((item for item in self.database.vulnerabilities(limit=1000) if item["cve_id"] == indicator.normalized_value), None)
        score = self._score(indicator, vulnerability=vulnerability)
        indicator.threat_score = max(indicator.threat_score, score.score)
        indicator.confidence = max(indicator.confidence, score.confidence)
        indicator.severity = score.severity
        if indicator.verification_status == Lifecycle.NEW:
            indicator.verification_status = Lifecycle.ACTIVE
        result = await asyncio.to_thread(self.database.upsert_indicator, indicator)
        await asyncio.to_thread(self.threat_correlator.map_indicator, result)
        metrics.inc("indicators_total" if result.get("created") else "indicators_active", 1)
        self.database.audit(indicator.source, "indicator.upsert", result["indicator_id"], "success",
                            {"created": result.get("created"), "score": result["threat_score"]})
        self.logger.info("indicator upserted", extra={"event_type": "ioc_update", "source": indicator.source,
                                                     "outcome": "created" if result.get("created") else "updated"})
        if publish and result["threat_score"] >= 60 and result["confidence"] >= 0.65:
            event = IntelligenceEvent(event_type=EventType.IOC_UPDATE, source="threat_intelligence",
                indicator=IndicatorReference(type=kind, value=result["normalized_value"]), severity=result["severity"],
                confidence=result["confidence"], context={"indicator_id": result["indicator_id"], "threat_score": result["threat_score"],
                "sources": [item["name"] for item in result["sources"]], "malware": result["malware_family"],
                "mitre_attack_ids": result["mitre_attack_ids"], "requires_human_approval": True})
            await self.emit(event)
        return result

    async def emit(self, event: IntelligenceEvent) -> str:
        self.database.save_event(event)
        transport = await self.bus.publish(event)
        self.last_ti_event = utcnow()
        metrics.inc("soc_messages_sent")
        return transport

    async def emit_feed_health(self, name: str, status: str, detail: Dict[str, Any]) -> None:
        severity = "informational" if status == "healthy" else "medium"
        event = IntelligenceEvent(event_type=EventType.FEED_HEALTH, source="threat_intelligence", severity=severity,
                                  confidence=1, context={"feed": name, "status": status, **detail})
        await self.emit(event)

    async def ingest_collected(self, item: CollectedItem, source: str, reliability: float) -> int:
        if item.kind == "indicator":
            await self.ingest_indicator(ThreatIndicator(source=source, source_reliability=reliability, **item.payload))
            return 1
        if item.kind == "stix":
            result = await asyncio.to_thread(self.stix.ingest, item.payload, source, reliability)
            return int(result["indicators"] + result["entities"] + result["relationships"] + result["vulnerabilities"])
        if item.kind == "vulnerability":
            payload = dict(item.payload)
            cve_id = normalize_indicator("cve", str(payload.pop("cve_id")))
            self.database.upsert_vulnerability(cve_id, payload)
            indicator = ThreatIndicator(indicator_type="cve", indicator_value=cve_id, source=source,
                source_url=payload.get("source_url"), source_reliability=reliability,
                confidence=0.98 if payload.get("kev") else 0.8, description=str(payload.get("description", "")),
                tags=["cisa-kev"] if payload.get("kev") else ["cve"], raw_data=payload)
            await self.ingest_indicator(indicator)
            return 1
        if item.kind == "event":
            payload = item.payload
            kind = canonical_type(payload["indicator_type"])
            event = IntelligenceEvent(event_type=EventType.IOC_OBSERVATION, source=payload.get("source", source),
                timestamp=self._parse_time(payload.get("timestamp")), indicator=IndicatorReference(type=kind, value=payload["value"]),
                confidence=float(payload.get("confidence", 0.5)), severity=payload.get("severity", "informational"),
                context=payload.get("context", {}))
            await self.process_soc_event(event, enforce_replay=False)
            return 1
        raise ValueError(f"unsupported collected item kind: {item.kind}")

    def lookup(self, value: str, indicator_type: Optional[str] = None) -> Dict[str, Any]:
        self.database.expire_due()
        kind = canonical_type(indicator_type).value if indicator_type else detect_type(value).value
        normalized = normalize_indicator(kind, value)
        result = self.database.get_indicator(kind, normalized)
        if not result:
            return {"found": False, "indicator_type": kind, "normalized_value": normalized, "malicious": False,
                    "confidence": 0, "threat_score": 0, "sources": [], "sightings": []}
        malicious = result["active"] and result["threat_score"] >= 40 and result["verification_status"] not in {"false_positive", "revoked", "expired"}
        return {"found": True, "malicious": malicious, **result}

    async def enrich(self, value: str, indicator_type: Optional[str] = None, allow_external: bool = False) -> Dict[str, Any]:
        kind = canonical_type(indicator_type).value if indicator_type else detect_type(value).value
        started = asyncio.get_running_loop().time()
        result = await self.enrichment.enrich(kind, value, allow_external=allow_external)
        metrics.inc("enrichment_total")
        metrics.inc("enrichment_seconds_total", asyncio.get_running_loop().time() - started)
        event = IntelligenceEvent(event_type=EventType.THREAT_ENRICHMENT, source="threat_intelligence",
            indicator=IndicatorReference(type=kind, value=value), confidence=0.7,
            context={"external_requested": allow_external, "providers": [entry.get("provider") for entry in result.get("external", [])]})
        await self.emit(event)
        return result

    async def create_sighting(self, indicator: Dict[str, Any], *, asset: Optional[AssetReference], source: str,
                              confidence: float, context: Dict[str, Any], timestamp: Optional[datetime] = None,
                              correlation_id: Optional[UUID] = None) -> Dict[str, Any]:
        sighting = Sighting(indicator_id=indicator["indicator_id"], asset=asset, source=source, confidence=confidence,
                            context=context, timestamp=timestamp or utcnow(), correlation_id=correlation_id or uuid4())
        result = await asyncio.to_thread(self.database.add_sighting, indicator["indicator_id"], sighting)
        return result

    async def process_soc_event(self, event: IntelligenceEvent, enforce_replay: bool = True) -> Dict[str, Any]:
        if enforce_replay:
            self.replay.validate(event, self.database.event_exists)
        if not self.database.save_event(event):
            raise SecurityError("event_id was already processed")
        self.last_soc_event = utcnow()
        metrics.inc("soc_messages_received")
        indicator_result = None
        sighting_result = None
        if event.indicator:
            kind = canonical_type(event.indicator.type).value
            normalized = normalize_indicator(kind, event.indicator.value)
            indicator_result = self.database.get_indicator(kind, normalized)
            if not indicator_result:
                # SOC observations are retained as low-confidence observed data,
                # not silently promoted to malicious intelligence.
                observed = ThreatIndicator(indicator_type=kind, indicator_value=normalized, source=f"{event.source}-observation",
                    source_reliability=0.55, confidence=min(0.6, event.confidence), threat_score=0,
                    severity="informational", verification_status="new", raw_data={"event_id": str(event.event_id)})
                indicator_result = await self.ingest_indicator(observed, publish=False)
            sighting_result = await self.create_sighting(indicator_result, asset=event.asset, source=event.source,
                confidence=event.confidence, context=event.context, timestamp=event.timestamp, correlation_id=event.correlation_id)
            # Re-score with current source diversity and actual sightings.
            model = ThreatIndicator(**{key: value for key, value in indicator_result.items()
                                      if key in ThreatIndicator.model_fields and key not in {"sources", "confidence_history", "sightings"}})
            score = self._score(model, independent_sources=len(indicator_result.get("sources", [])),
                                sightings=len(indicator_result.get("sightings", [])) + 1)
            model.threat_score = max(float(indicator_result["threat_score"]), score.score)
            model.confidence = max(float(indicator_result["confidence"]), score.confidence)
            model.severity = score.severity
            indicator_result = await self.ingest_indicator(model, publish=False)

        decision = await asyncio.to_thread(self.event_correlator.correlate, event, indicator_result)
        correlation = None
        emitted = []
        if decision.matched and indicator_result:
            correlation = self.database.save_correlation(str(event.correlation_id), decision.rule_name,
                indicator_result["indicator_id"], event.asset.id if event.asset else None, decision.risk_score,
                decision.severity, decision.evidence)
            metrics.inc("ioc_matches_total")
            metrics.inc("correlations_total")
            match_event = IntelligenceEvent(event_type=EventType.IOC_MATCH, source="threat_intelligence",
                indicator=event.indicator, asset=event.asset, severity=decision.severity, confidence=decision.confidence,
                correlation_id=event.correlation_id, context={"threat_score": indicator_result["threat_score"],
                    "correlated_risk_score": decision.risk_score, "risk_delta": decision.risk_delta,
                    "rule": decision.rule_name, "sources": [item["name"] for item in indicator_result["sources"]],
                    "malware": indicator_result["malware_family"], "mitre_attack_ids": indicator_result["mitre_attack_ids"],
                    "evidence": decision.evidence, "requires_human_approval": True, "defensive_action_executed": False})
            emitted.append(await self.emit(match_event))
            correlation_event = IntelligenceEvent(event_type=EventType.CORRELATION_DETECTED, source="correlation",
                indicator=event.indicator, asset=event.asset, severity=decision.severity, confidence=decision.confidence,
                correlation_id=event.correlation_id, context={"rule": decision.rule_name, "risk_score": decision.risk_score,
                    "incident_recommended": decision.incident_recommended, "evidence": decision.evidence,
                    "defensive_action_executed": False})
            emitted.append(await self.emit(correlation_event))
            risk_event = IntelligenceEvent(event_type=EventType.RISK_UPDATE, source="correlation",
                indicator=event.indicator, asset=event.asset, severity=decision.severity, confidence=decision.confidence,
                correlation_id=event.correlation_id, context={"previous_threat_score": indicator_result["threat_score"],
                    "correlated_risk_score": decision.risk_score, "risk_delta": decision.risk_delta,
                    "evidence": decision.evidence, "defensive_action_executed": False})
            emitted.append(await self.emit(risk_event))
            if decision.incident_recommended:
                incident = IntelligenceEvent(event_type=EventType.INCIDENT_CREATED, source="correlation",
                    indicator=event.indicator, asset=event.asset, severity=decision.severity, confidence=decision.confidence,
                    correlation_id=event.correlation_id, context={"status": "recommended", "reason": decision.rule_name,
                        "requires_safety_authorization": True, "requires_human_approval": True, "defensive_action_executed": False})
                emitted.append(await self.emit(incident))
        self.database.audit(event.source, "event.process", str(event.event_id), "success",
                            {"matched": decision.matched, "rule": decision.rule_name}, str(event.correlation_id))
        return {
            "status": "processed", "event_id": str(event.event_id), "correlation_id": str(event.correlation_id),
            "intelligence": indicator_result, "sighting": sighting_result,
            "correlation": {**correlation, "confidence": decision.confidence, "risk_delta": decision.risk_delta,
                            "incident_recommended": decision.incident_recommended} if correlation else None,
            "soc_alert": {"enriched": bool(indicator_result), "severity": decision.severity,
                "risk_score": decision.risk_score, "confidence": decision.confidence,
                "investigate": ["validate the asset observation", "review related network and endpoint telemetry",
                                "confirm source provenance before containment"],
                "requires_human_approval": True, "defensive_action_executed": False},
            "transports": emitted,
        }

    def make_report(self, indicator_id: str) -> Dict[str, Any]:
        indicator = self.database.get_indicator_by_id(indicator_id)
        if not indicator:
            raise KeyError(indicator_id)
        relationships = self.database.relationships(indicator_id)
        correlations = [item for item in self.database.correlations() if item.get("indicator_id") == indicator_id]
        evidence = [f"indicator:{indicator_id}"] + [f"source:{item['name']}" for item in indicator["sources"]]
        conclusion = AIConclusion(
            conclusion=f"{indicator['normalized_value']} is classified {indicator['severity']} with score {indicator['threat_score']}",
            confidence=indicator["confidence"], evidence=evidence,
            sources=[item["name"] for item in indicator["sources"]] or [indicator["source"]],
            reasoning_summary="The conclusion is derived only from stored provenance, score factors, sightings and explicit relationships.",
        )
        report_id = f"report--{uuid4()}"
        timeline = ([{"timestamp": indicator["created_at"], "event": "IOC received"}] +
                    [{"timestamp": item["timestamp"], "event": "SOC sighting", "asset": item.get("asset")} for item in indicator["sightings"]] +
                    [{"timestamp": item["created_at"], "event": "correlation detected", "rule": item["rule_name"]} for item in correlations])
        report = {"report_id": report_id, "title": f"Threat intelligence report: {indicator['normalized_value']}",
            "threat_summary": conclusion.model_dump(mode="json"), "affected_assets": [item.get("asset") for item in indicator["sightings"] if item.get("asset")],
            "indicators": [indicator], "confidence": indicator["confidence"], "threat_score": indicator["threat_score"],
            "sources": indicator["sources"], "first_seen": indicator["first_seen"], "last_seen": indicator["last_seen"],
            "mitre_attack": indicator["mitre_attack_ids"], "malware": indicator["malware_family"], "actors": indicator["threat_actor"],
            "campaigns": indicator["campaign"], "cves": indicator["related_cves"], "soc_sightings": indicator["sightings"],
            "relationships": relationships, "correlations": correlations,
            "defensive_recommendations": ["validate the finding with independent telemetry", "scope affected assets",
                "use existing Safety, Authorization and Human Approval layers for any containment"],
            "evidence": evidence, "timeline": sorted(timeline, key=lambda item: item["timestamp"])}
        self.database.save_report(report_id, report["title"], report)
        return report

    async def health(self) -> Dict[str, Any]:
        try:
            bus = await self.bus.health()
        except Exception as exc:
            bus = {"status": "error", "active": "none", "last_error": str(exc)[:256]}
        feeds = self.feeds.status()
        last_feed = max((item.get("last_success") for item in feeds if item.get("last_success")), default=None)
        try:
            queue_depth = self.database.queue_depth()
            database_state = "connected"
        except Exception as exc:
            queue_depth = None
            database_state = f"error: {str(exc)[:128]}"
        status = "healthy" if self.started and bus["status"] == "connected" and database_state == "connected" else "degraded"
        return {"service": "threat_intelligence", "status": status,
            "soc_connection": "connected" if bus.get("active") in {"redis", "nats", "http"} and bus["status"] == "connected" else "degraded",
            "transport": bus.get("active", "none"), "last_soc_event": self.last_soc_event.isoformat() if self.last_soc_event else None,
            "last_ti_event": self.last_ti_event.isoformat() if self.last_ti_event else None, "last_feed_sync": last_feed,
            "queue_depth": queue_depth, "database": database_state, "started": self.started,
            "uptime_seconds": (utcnow() - self.started_at).total_seconds() if self.started_at else 0,
            "transport_detail": bus}


engine = ThreatIntelligenceEngine()
