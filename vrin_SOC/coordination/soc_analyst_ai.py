"""SOC Analyst AI — triage, correlation, investigation, recommendations.

Consumes infrastructure telemetry, threat intelligence, Data Science results,
and historical knowledge; produces timelines, evidence bundles, incident
summaries, and *recommendations*. It never executes high-impact actions
itself — response routing goes through the Commander → Ethics → human
approval chain (spec §21).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import SecurityEvent, utc_now_iso

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class SOCAnalystAI(BaseAgent):
    name = "SOCAnalystAI"
    kind = "analyst"
    capabilities = ["triage", "correlation", "timeline", "evidence", "investigation", "recommendations"]

    def __init__(self, bus: Optional[EventBus] = None, correlation_minutes: int = 15) -> None:
        super().__init__(bus)
        self.correlation_window = timedelta(minutes=correlation_minutes)

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------
    def triage(self, event: SecurityEvent) -> Dict[str, Any]:
        """Prioritize an event: severity, queue, and whether to investigate."""
        risk = event.risk or {}
        anomaly = (event.analysis or {}).get("anomaly") or {}
        score = float(risk.get("risk_score", 0.0))
        if risk.get("severity") in {"high", "critical"} or anomaly.get("is_anomaly"):
            priority, investigate = "high", True
        elif score >= 0.3:
            priority, investigate = "medium", True
        else:
            priority, investigate = "low", False
        return {
            "event_id": event.event_id,
            "priority": priority,
            "investigate": investigate,
            "risk_score": score,
            "anomaly": bool(anomaly.get("is_anomaly")),
            "mode": event.provenance.mode.value,
        }

    # ------------------------------------------------------------------
    # Correlation (entity/IP/time-window join across the bus history)
    # ------------------------------------------------------------------
    def correlate(self, event: SecurityEvent) -> Dict[str, Any]:
        related: List[Dict[str, Any]] = []
        if not event.correlation_id:
            return {"event_id": event.event_id, "related_events": [], "entity_links": {}}

        primary = (event.entity and event.entity.primary()) or None
        ts = _parse(event.timestamp)
        for other in self.bus._history:  # noqa: SLF001 — same package, deliberate
            if other.event_id == event.event_id or other.correlation_id != event.correlation_id:
                continue
            other_ts = _parse(other.timestamp)
            in_window = abs((other_ts - ts).total_seconds()) <= self.correlation_window.total_seconds()
            other_primary = (other.entity and other.entity.primary()) or None
            shared_entity = bool(primary and other_primary and (
                other_primary == primary
                or other_primary in str(primary)
                or primary in str(other_primary)
            ))
            shared_ip = bool(event.entity and event.entity.ip and other.entity and event.entity.ip == other.entity.ip)
            if in_window and (shared_entity or shared_ip):
                related.append({
                    "event_id": other.event_id,
                    "event_type": other.event_type,
                    "timestamp": other.timestamp,
                    "severity": other.severity,
                    "source_agent": other.source_agent,
                })
        related_risks = [float((event.risk or {}).get("risk_score", 0.0))]
        for item in related:
            other = self.bus.find(item["event_id"])
            if other is not None and other.risk:
                related_risks.append(float(other.risk.get("risk_score", 0.0)))
        return {
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "window_minutes": int(self.correlation_window.total_seconds() // 60),
            "related_events": related[:25],
            "related_count": len(related),
            "aggregate_risk": round(max(related_risks), 4) if related_risks else 0.0,
        }

    # ------------------------------------------------------------------
    # Evidence + investigation
    # ------------------------------------------------------------------
    def gather_evidence(self, event: SecurityEvent) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {
            "telemetry": _pick(event.data, ("cpu", "memory", "disk", "processes", "listeners", "network", "authentication")),
            "threat_intelligence": event.threat_intelligence,
            "data_science": {
                "anomaly": (event.analysis or {}).get("anomaly"),
                "features": (event.analysis or {}).get("features"),
            },
            "risk": event.risk,
            "siem_context": self._siem_context(event),
        }
        return evidence

    def _siem_context(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Recent SIEM log lines mentioning the event's entity (read-only)."""
        key = (event.entity and (event.entity.ip or event.entity.host)) or ""
        if not key:
            return []
        try:
            from vrin_SOC.database.db import get_logs

            rows = get_logs(50)
        except Exception:  # noqa: BLE001
            return []
        hits = []
        for row in rows:
            text = f"{row.get('command', '')} {row.get('result', '')}"
            if key in text:
                hits.append({"timestamp": row.get("timestamp"), "command": row.get("command", "")[:200],
                             "risk_level": row.get("risk_level", "Low")})
        return hits[:10]

    def investigate(self, event: SecurityEvent) -> Dict[str, Any]:
        """Full investigation: triage → correlation → evidence → recommendations."""
        return self.run_guarded(self._investigate, event)

    def _investigate(self, event: SecurityEvent) -> Dict[str, Any]:
        triage = self.triage(event)
        correlation = self.correlate(event)
        evidence = self.gather_evidence(event)

        recommendations = self._recommend(event, correlation, evidence)
        summary = self._summarize(event, triage, correlation, recommendations)
        event.correlation = {**event.correlation, "investigation": {
            "summary": summary, "recommendations": recommendations,
            "correlated": correlation["related_count"], "investigated_at": utc_now_iso(),
        }}
        event.status = _advance_status(event.status, "correlated")
        return {
            "status": "success",
            "event_id": event.event_id,
            "triage": triage,
            "correlation": correlation,
            "evidence": evidence,
            "recommendations": recommendations,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Recommendations (never execution)
    # ------------------------------------------------------------------
    def _recommend(self, event: SecurityEvent, correlation: Dict[str, Any],
                   evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        recs: List[Dict[str, Any]] = []
        ip = event.entity and event.entity.ip
        risk = float((event.risk or {}).get("risk_score", 0.0))
        anomaly = (event.analysis or {}).get("anomaly") or {}
        malicious_ti = bool((event.threat_intelligence or {}).get("malicious_found"))

        # Incident-level risk = strongest signal across the correlation
        # (a 70%-risk auth event + a 55%-risk network event is more dangerous
        # than either alone; the final decision still belongs to the human).
        related_risks = [risk]
        for rel in correlation.get("related_events", []):
            related = self.bus.find(rel["event_id"])
            if related is not None and related.risk:
                related_risks.append(float(related.risk.get("risk_score", 0.0)))
        aggregate_risk = max(related_risks) if related_risks else risk

        # Block candidates are ATTACKING sources / C2 destinations — never the
        # victim's own management address.
        candidates: List[str] = []
        network = (event.data or {}).get("network") if isinstance((event.data or {}).get("network"), dict) else {}
        for source in network.get("source_ips", []) or []:
            source = str(source)
            if source and source not in candidates:
                candidates.append(source)
        outbound = network.get("outbound") if isinstance(network.get("outbound"), dict) else {}
        if outbound.get("ip"):
            c2 = str(outbound["ip"])
            if c2 not in candidates:
                candidates.append(c2)
        if not candidates and ip:
            candidates.append(ip)

        # Documented triage threshold: incident risk >= 0.5 (medium/high
        # boundary) with an identifiable attacking source escalates to a
        # human approval decision, or immediately at >= 0.6 / malicious IOC.
        if candidates and (aggregate_risk >= 0.5 or malicious_ti):
            for candidate in candidates[:2]:
                recs.append({
                    "action": "block_ip",
                    "target": candidate,
                    "impact": "high",
                    "requires_human_approval": True,
                    "reason": f"incident risk {aggregate_risk:.2f} (this event {risk:.2f}) on activity "
                              f"sourced from {candidate}" + (
                                  " with malicious IOC confirmed by threat intelligence"
                                  if malicious_ti else ""),
                })
        host = event.entity and event.entity.host
        if host and (anomaly.get("is_anomaly") or risk >= 0.4):
            recs.append({
                "action": "investigate_host",
                "target": host,
                "impact": "low",
                "requires_human_approval": False,
                "reason": "anomaly/risk on host — review processes, listeners, and auth events",
            })
        if not recs:
            recs.append({
                "action": "continue_monitoring",
                "target": host or ip or "system",
                "impact": "none",
                "requires_human_approval": False,
                "reason": "signals below action threshold; keep monitoring",
            })
        if correlation["related_count"] > 1:
            recs.append({
                "action": "correlated_review",
                "target": event.correlation_id or "",
                "impact": "low",
                "requires_human_approval": False,
                "reason": f"{correlation['related_count']} related events in the correlation window",
            })
        return recs

    def _summarize(self, event: SecurityEvent, triage: Dict[str, Any], correlation: Dict[str, Any],
                   recommendations: List[Dict[str, Any]]) -> str:
        entity = (event.entity and event.entity.primary()) or "system"
        parts = [
            f"[{event.severity.upper()}] {event.event_type} on {entity} "
            f"(risk {float((event.risk or {}).get('risk_score', 0.0)):.2f}, "
            f"anomaly {'yes' if ((event.analysis or {}).get('anomaly') or {}).get('is_anomaly') else 'no'}).",
        ]
        aggregate = correlation.get("aggregate_risk")
        if aggregate is not None and float(aggregate) > float((event.risk or {}).get("risk_score", 0.0)) + 1e-9:
            parts.append(f"Incident-level aggregated risk across correlation: {float(aggregate):.2f}.")
        if correlation["related_count"]:
            parts.append(f"{correlation['related_count']} related event(s) correlated in a "
                         f"{correlation['window_minutes']}-minute window.")
        primary_rec = recommendations[0]
        parts.append(f"Primary recommendation: {primary_rec['action']} ({primary_rec['reason']}).")
        if (event.threat_intelligence or {}).get("mode") == "unavailable":
            parts.append("Threat intelligence enrichment was unavailable and is labeled as such.")
        if event.provenance.mode.value != "real":
            parts.append(f"Data mode: {event.provenance.mode.value.upper()} — not live telemetry.")
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Bus wiring
    # ------------------------------------------------------------------
    def on_risk_assessed(self, event: SecurityEvent) -> None:
        if event.source_agent == self.name:
            return
        if event.event_type not in {"security_event", "telemetry"}:
            return
        if "investigation" in (event.correlation or {}):
            return
        if not event.correlation_id:
            return  # only events owned by an investigation are auto-triaged
        triage = self.triage(event)
        if triage["investigate"]:
            self.run_guarded(self._investigate, event)

    def health(self) -> Dict[str, Any]:
        return super().health()


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _pick(data: Dict[str, Any], keys: tuple) -> Dict[str, Any]:
    return {k: data[k] for k in keys if k in data} if isinstance(data, dict) else {}


def _advance_status(status, target: str):
    from .schemas import EventStatus

    order = [EventStatus.NEW, EventStatus.INGESTED, EventStatus.ENRICHED, EventStatus.ANALYZED,
             EventStatus.RISK_ASSESSED, EventStatus.CORRELATED]
    try:
        target_status = EventStatus(target)
    except ValueError:
        return status
    if status in order and target_status in order and order.index(status) < order.index(target_status):
        return target_status
    return status


soc_analyst_ai = SOCAnalystAI()

__all__ = ["SOCAnalystAI", "soc_analyst_ai"]
