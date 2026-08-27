"""Threat Intelligence AI — external threat context, never fabricated.

Integrates with the existing ``core.intelligence_bus.IntelligenceGateway``
(which already handles the Vrin_TI service, its durable offline queue, and the
local TI database). This agent:

1. extracts indicators (IP / domain / hash) from a security event;
2. enriches them through the gateway (remote service when reachable, local
   TI database otherwise);
3. publishes structured enrichment back onto the event bus.

No-fabrication rule: when no intelligence is available the agent returns
``status: "unavailable"`` / ``degraded: true`` with ``malicious: None``.
It never invents reputation, campaign attribution, or IOCs.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import re
from typing import Any, Dict, List, Optional

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import EventMode, SecurityEvent, utc_now_iso

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.IGNORECASE
)
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

#: Domains that are infrastructure noise for IOC extraction.
_NOISE_DOMAINS = {
    "localhost", "example.com", "example.org", "example.net",
    "schema.org", "w3.org", "iana.org", "localhost.localdomain",
}


class ThreatIntelAI(BaseAgent):
    name = "ThreatIntelAI"
    kind = "sensor"
    capabilities = ["ioc_extraction", "ip_intelligence", "domain_intelligence", "hash_intelligence", "enrichment"]

    def __init__(self, bus: Optional[EventBus] = None, timeout: float = 2.5) -> None:
        super().__init__(bus)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Indicator extraction
    # ------------------------------------------------------------------
    def extract_indicators(self, event: SecurityEvent) -> List[Dict[str, str]]:
        text_parts: List[str] = []
        if event.entity:
            text_parts += [v for v in (event.entity.ip, event.entity.domain, event.entity.host) if v]
        text_parts.append(_flatten(event.data))
        text = " ".join(text_parts).lower()

        indicators: List[Dict[str, str]] = []
        seen: set = set()

        for ip in _IP_RE.findall(text):
            if ip not in seen and not ip.startswith(("0.", "255.")):
                seen.add(ip)
                indicators.append({"value": ip, "type": "ipv4"})
        for domain in _DOMAIN_RE.findall(text):
            if domain in _NOISE_DOMAINS or domain in seen:
                continue
            seen.add(domain)
            indicators.append({"value": domain, "type": "domain"})
        for h in _HASH_RE.findall(text):
            digest = h.lower()
            if digest in seen:
                continue
            kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(digest)]
            seen.add(digest)
            indicators.append({"value": digest, "type": kind})

        return indicators[:20]

    # ------------------------------------------------------------------
    # Enrichment through the existing gateway (remote → local → unavailable)
    # ------------------------------------------------------------------
    def _gateway(self):
        from vrin_SOC.core.intelligence_bus import intelligence_gateway

        return intelligence_gateway

    def _run_async(self, coro) -> Any:
        """Run a gateway coroutine from any context without loop conflicts."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(asyncio.wait_for(coro, timeout=self.timeout))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(asyncio.wait_for(coro, timeout=self.timeout))).result(
                timeout=self.timeout + 2.0
            )

    def lookup(self, value: str, indicator_type: Optional[str] = None) -> Dict[str, Any]:
        """Single-indicator enrichment. Degrades to 'unavailable', never invents."""
        started = self._before()
        try:
            gateway = self._gateway()
            result = self._run_async(gateway.lookup(value, indicator_type))
            if not isinstance(result, dict):
                result = {"found": False, "malicious": None, "status": "unavailable"}
            result.setdefault("indicator", value)
            result.setdefault("status", "unavailable" if result.get("found") is None else "ok")
            self._after(started, ok=True)
            return result
        except Exception as exc:  # noqa: BLE001
            self._after(started, ok=False)
            self.metrics.record_error(str(exc))
            return {
                "indicator": value,
                "found": None,
                "malicious": None,
                "status": "unavailable",
                "degraded": True,
                "reason": str(exc)[:256],
                "source": "none",
                "note": "Threat intelligence unavailable — enrichment marked unavailable, nothing fabricated.",
            }

    def enrich(self, event: SecurityEvent) -> Dict[str, Any]:
        """Enrich all indicators of an event and attach results to it."""
        return self.run_guarded(self._enrich, event)

    def _enrich(self, event: SecurityEvent) -> Dict[str, Any]:
        indicators = self.extract_indicators(event)
        enrichment: Dict[str, Any] = {
            "indicators": [],
            "malicious_found": False,
            "mode": EventMode.REAL.value,
            "source": "threat_intel_ai",
            "checked_at": utc_now_iso(),
        }
        for indicator in indicators:
            result = self.lookup(indicator["value"], indicator["type"])
            found = result.get("found")
            malicious = result.get("malicious")
            entry = {
                "indicator": indicator["value"],
                "type": indicator["type"],
                "found": found,
                "malicious": malicious,
                "status": result.get("status", "unavailable"),
                "degraded": bool(result.get("degraded")),
                "threat_score": result.get("threat_score"),
                "sources": result.get("sources", []),
            }
            enrichment["indicators"].append(entry)
            if malicious is True:
                enrichment["malicious_found"] = True
                enrichment["malicious_indicators"].append(indicator["value"])
            if result.get("degraded") and result.get("status") == "unavailable":
                enrichment["mode"] = EventMode.UNAVAILABLE.value

        event.threat_intelligence = {**event.threat_intelligence, **enrichment}
        if enrichment["mode"] != EventMode.UNAVAILABLE.value:
            event.status = _enriched_status(event.status)
        return {
            "status": "success",
            "event_id": event.event_id,
            "indicators_checked": len(indicators),
            "malicious_found": enrichment["malicious_found"],
            "enrichment_mode": enrichment["mode"],
            "enrichment": enrichment,
        }

    # ------------------------------------------------------------------
    # Bus wiring
    # ------------------------------------------------------------------
    def on_security_event(self, event: SecurityEvent) -> None:
        """Subscribe hook: enrich security/telemetry events that carry indicators."""
        if event.event_type not in {"security_event", "telemetry", "auth_failure", "network_event"}:
            return
        if event.source_agent == self.name:
            return
        self.run_guarded(self._enrich, event)

    def health(self) -> Dict[str, Any]:
        base = super().health()
        try:
            gateway = self._gateway()
            base["ti_transport"] = gateway.transport_health()
        except Exception:  # noqa: BLE001
            base["ti_transport"] = {"status": "unavailable"}
        return base


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(v) for v in value)
    return str(value) if value is not None else ""


def _enriched_status(status):
    from .schemas import EventStatus

    order = [EventStatus.NEW, EventStatus.INGESTED, EventStatus.ENRICHED, EventStatus.ANALYZED,
             EventStatus.RISK_ASSESSED, EventStatus.CORRELATED]
    if status in order and order.index(status) < order.index(EventStatus.ENRICHED):
        return EventStatus.ENRICHED
    return status


threat_intel_ai = ThreatIntelAI()

__all__ = ["ThreatIntelAI", "threat_intel_ai", "hashlib"]
