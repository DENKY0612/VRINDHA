"""Evidence-based SOC event ↔ TI correlation rules."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..database import ThreatDatabase
from ..models import IntelligenceEvent
from ..scoring.threat_score import severity_for


@dataclass(frozen=True)
class CorrelationDecision:
    matched: bool
    rule_name: str
    confidence: float
    risk_score: float
    severity: str
    evidence: List[Dict[str, Any]]
    risk_delta: float
    incident_recommended: bool


class EventCorrelator:
    def __init__(self, database: ThreatDatabase, window_minutes: int = 30):
        self.database = database
        self.window = timedelta(minutes=window_minutes)

    def correlate(self, event: IntelligenceEvent, indicator: Optional[Dict[str, Any]]) -> CorrelationDecision:
        if not indicator:
            return CorrelationDecision(False, "no_intelligence_match", 0, 0, "informational", [], 0, False)
        threat_score = float(indicator.get("threat_score", 0))
        sources = indicator.get("sources", [])
        observation_only = bool(sources) and all(str(item.get("name", "")).endswith("-observation") for item in sources)
        if observation_only and threat_score < 40:
            return CorrelationDecision(False, "unverified_soc_observation", 0, threat_score, "informational", [], 0, False)
        confidence = float(indicator.get("confidence", 0))
        event_confidence = float(event.confidence)
        evidence: List[Dict[str, Any]] = [
            {"type": "ti_match", "indicator_id": indicator["indicator_id"], "threat_score": threat_score, "confidence": confidence},
            {"type": "soc_observation", "event_id": str(event.event_id), "event_confidence": event_confidence},
        ]
        contextual = 0.0
        rule = "ioc_observation"
        asset = event.asset
        context_text = str(event.context).lower()
        kind = indicator["indicator_type"]

        if asset:
            contextual += asset.criticality * 8
            evidence.append({"type": "asset", "id": asset.id, "criticality": asset.criticality, "exposed": asset.exposed})
            cutoff = datetime.now(timezone.utc) - self.window
            recurring = 0
            for sighting in self.database.list_sightings(limit=500):
                if sighting.get("asset_id") != asset.id:
                    continue
                try:
                    timestamp = datetime.fromisoformat(sighting["timestamp"])
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    if timestamp >= cutoff:
                        recurring += 1
                except (ValueError, TypeError):
                    continue
            if recurring:
                contextual += min(10, recurring * 2)
                evidence.append({"type": "time_window", "minutes": self.window.total_seconds() / 60, "same_asset_sightings": recurring})

        if kind in {"md5", "sha1", "sha256"} and indicator.get("malware_family") and any(term in context_text for term in ("endpoint", "edr", "file", "process", "yara")):
            rule = "malware_hash_endpoint_detection"
            contextual += 28
            evidence.append({"type": "malware_association", "families": indicator["malware_family"]})
        elif kind in {"ipv4", "ipv6", "domain", "url"} and threat_score >= 60 and any(term in context_text for term in ("connection", "flow", "dns", "http", "tls", "suricata", "zeek")):
            rule = "malicious_network_ioc_internal_connection"
            contextual += 18
        elif kind == "cve":
            vulnerability = next((item for item in self.database.vulnerabilities(limit=1000) if item["cve_id"] == indicator["normalized_value"]), None)
            if vulnerability and vulnerability.get("kev") and asset and asset.exposed and asset.criticality >= 0.7:
                rule = "kev_exposed_critical_asset"
                contextual += 35
                evidence.append({"type": "cisa_kev", "cve": vulnerability["cve_id"], "known_exploited": True})
        elif indicator.get("mitre_attack_ids") and any(technique.lower() in context_text for technique in indicator["mitre_attack_ids"]):
            rule = "attack_technique_behavior_ioc"
            contextual += 22
            evidence.append({"type": "attack_mapping", "techniques": indicator["mitre_attack_ids"]})

        # Context can raise priority only when backed by both a TI match and a
        # validated SOC observation. It cannot turn a weak unknown IOC critical.
        combined_confidence = min(0.99, confidence * 0.65 + event_confidence * 0.25 + (0.1 if len(evidence) >= 3 else 0))
        risk = min(100, threat_score * 0.72 + contextual + event_confidence * 8)
        risk_delta = max(0, min(30, risk - threat_score))
        severity = severity_for(risk)
        matched = threat_score >= 20 and combined_confidence >= 0.35
        incident = matched and risk >= 80 and combined_confidence >= 0.7
        return CorrelationDecision(matched, rule, round(combined_confidence, 4), round(risk, 2), severity,
                                   evidence, round(risk_delta, 2), incident)
