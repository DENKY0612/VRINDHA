"""
Risk Scoring System - Phase 4 (and Data Science Role #4)

Vrindha deliberately avoids binary AI decisions such as "malicious" vs
"benign".  This module produces an explainable 0-100 risk score by combining
independent detection layers:

* rule/signature indicators
* anomaly evidence
* threat-intelligence reputation
* behavioral context
* SIEM/log correlation
* AI/threat-agent reasoning

The result is advisory intelligence.  High-risk or high-impact responses are
routed to a human-validation gate before any containment action is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional
import math
import re

from vrin_SOC.core.error_handler import ErrorHandler


@dataclass(frozen=True)
class RiskSignal:
    """One independent detection layer's contribution."""

    layer: str
    score: float  # 0-100
    confidence: float  # 0-1
    evidence: List[str]
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "score": round(max(0.0, min(100.0, self.score)), 2),
            "confidence": round(max(0.0, min(1.0, self.confidence)), 3),
            "evidence": self.evidence,
            "active": self.active,
        }


class RiskScoring:
    """Risk-based, human-validated scoring engine.

    Scores are not labels of absolute truth.  They are a compact way to express
    severity + confidence + context, with explanations that analysts can
    validate and feed back into Vrindha.
    """

    #: Relative weights for independent detection layers.  Only active layers
    #: are normalized into the final score, so missing TI does not incorrectly
    #: mean "safe"; it simply lowers confidence and removes corroboration.
    LAYER_WEIGHTS: Mapping[str, float] = {
        "rule_signature_detection": 0.20,
        "anomaly_detection": 0.15,
        "threat_intelligence": 0.20,
        "behavioral_analysis": 0.15,
        "siem_log_correlation": 0.15,
        "ai_reasoning": 0.10,
        "declared_severity": 0.05,
    }

    SEVERITY_SCORE: Mapping[str, float] = {
        "informational": 5,
        "info": 5,
        "low": 20,
        "medium": 50,
        "moderate": 50,
        "high": 78,
        "critical": 93,
    }

    CONFIDENCE_VALUE: Mapping[str, float] = {
        "none": 0.0,
        "low": 0.35,
        "medium": 0.60,
        "moderate": 0.60,
        "high": 0.82,
        "critical": 0.92,
        "very_high": 0.95,
    }

    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 31338, 8081}

    def __init__(self):
        self.name = "RiskScoring"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def score(self, event: Dict[str, Any] | Any) -> Dict[str, Any]:
        """Return an explainable advisory risk assessment.

        The output keeps the legacy ``risk_score``/``risk_level``/``reason``
        fields while adding confidence, independent signal details,
        recommended action, and human-validation metadata.
        """
        try:
            event_dict = event if isinstance(event, dict) else {"raw": event}
            text = self._event_text(event_dict)
            text_lower = text.lower()
            ip = self._first_present(event_dict, "ip", "source_ip", "src_ip", "remote_ip") or "unknown"

            signals = self._build_signals(event_dict, text, text_lower)
            active = [s for s in signals if s.active]
            total_weight = sum(self.LAYER_WEIGHTS.get(s.layer, 0.05) for s in active) or 1.0
            weighted_score = sum(
                s.score * self.LAYER_WEIGHTS.get(s.layer, 0.05) for s in active
            ) / total_weight

            # Corroboration bonus: several independent layers saying the same
            # thing should raise risk and confidence more than one isolated AI
            # prediction.
            corroborating = [s for s in active if s.score >= 55 and s.evidence]
            strong = [s for s in active if s.score >= 75 and s.evidence]
            if len(corroborating) >= 2:
                weighted_score += min(8.0, 3.0 * (len(corroborating) - 1))
            if len(strong) >= 3:
                weighted_score += 5.0
            risk_score = int(round(max(0.0, min(100.0, weighted_score))))

            risk_level = self._risk_level(risk_score)
            confidence_score = self._confidence_score(active, corroborating, event_dict)
            reasons = self._dedupe_reason([item for s in active for item in s.evidence])
            if not reasons:
                reasons = ["No significant multi-layer risk indicators; behavior appears normal"]

            requires_human = self._requires_human_validation(risk_score, text_lower, event_dict)
            recommended_action = self._recommended_action(risk_score, requires_human, ip)

            return {
                "ip": ip,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "confidence_score": confidence_score,
                "confidence": self._confidence_label(confidence_score),
                "decision_style": "risk_score_not_binary",
                "reason": " + ".join(reasons),
                "reasons": reasons,
                "explanation": reasons,
                "signals": [s.to_dict() for s in active],
                "signal_summary": {
                    "active_layers": len(active),
                    "corroborating_layers": len(corroborating),
                    "strong_layers": len(strong),
                    "layers": [s.layer for s in active],
                },
                "recommended_action": recommended_action,
                "requires_human_validation": requires_human,
                "human_validation": {
                    "required": requires_human,
                    "reason": "High risk or high-impact response must be analyst-validated before containment"
                    if requires_human else "No high-impact response recommended",
                    "allowed_without_validation": ["log", "alert", "monitor", "collect_more_evidence"],
                },
                "continuous_learning": {
                    "feedback_expected": True,
                    "labels": ["true_positive", "false_positive", "benign", "unknown"],
                    "note": "Analyst verdicts should be stored as feedback before changing rules/models.",
                },
                "timestamp": datetime.now().isoformat(),
                "model": "multi-layer risk scoring v2 (rules + anomaly + TI + behavior + SIEM + AI reasoning)",
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "RiskScoring.score")

    def score_ip_history(self, ip: str, events: List[Dict]) -> Dict:
        """Score based on history for an IP"""
        try:
            combined_text = " ".join([str(e) for e in events])
            result = self.score({"ip": ip, "events": events, "combined": combined_text, "correlated_alerts": events})
            result["history_count"] = len(events)
            return result
        except Exception as e:
            return ErrorHandler.handle_exception(e, "RiskScoring.score_ip_history")

    # ------------------------------------------------------------------
    # Signal builders
    # ------------------------------------------------------------------
    def _build_signals(self, event: Mapping[str, Any], text: str, text_lower: str) -> List[RiskSignal]:
        return [
            self._rule_signal(event, text_lower),
            self._anomaly_signal(event, text_lower),
            self._threat_intel_signal(event, text_lower),
            self._behavior_signal(event, text_lower),
            self._siem_correlation_signal(event, text_lower),
            self._ai_reasoning_signal(event, text_lower),
            self._severity_signal(event),
        ]

    def _rule_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        evidence: List[str] = []
        score = 0.0
        keyword_rules = [
            (("ransomware", "rootkit", "backdoor"), 90, "High-severity malware/rootkit/backdoor indicator"),
            (("malware", "trojan", "worm", "botnet"), 78, "Malware indicator detected"),
            (("credential stuffing", "brute force", "password spray"), 68, "Credential attack pattern detected"),
            (("exploit", "intrusion", "breach"), 62, "Exploit/intrusion/breach keyword detected"),
            (("phishing", "ddos", "data exfiltration", "exfiltration"), 58, "Known attack technique keyword detected"),
            (("attack", "unauthorized"), 45, "Attack/unauthorized-access keyword detected"),
        ]
        for keywords, value, reason in keyword_rules:
            if any(k in text_lower for k in keywords):
                score = max(score, value)
                evidence.append(reason)

        failed = self._failed_login_count(event, text_lower)
        if failed:
            failed_score = min(85, 20 + failed * 10)
            score = max(score, failed_score)
            evidence.append(f"Multiple failed authentication attempts ({failed})")

        ports = self._suspicious_ports(event, text_lower)
        if ports:
            score = max(score, 65)
            evidence.append(f"Suspicious/unusual port access: {', '.join(map(str, sorted(ports)))}")

        if "scan" in text_lower and ("multiple" in text_lower or "recon" in text_lower or "nmap" in text_lower):
            score = max(score, 42)
            evidence.append("Reconnaissance/scan pattern detected")

        if not evidence:
            return RiskSignal("rule_signature_detection", 8, 0.55, [], active=True)
        return RiskSignal("rule_signature_detection", min(score, 100), 0.78, evidence)

    def _anomaly_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        explicit = self._first_present(event, "anomaly_score")
        if explicit is None and isinstance(event.get("analysis"), dict):
            anomaly = event["analysis"].get("anomaly")
            if isinstance(anomaly, dict):
                explicit = anomaly.get("anomaly_score")
        if explicit is not None:
            score = self._score_from_fraction_or_percent(explicit)
            evidence = [f"Anomaly detector score {score:.0f}/100"] if score >= 30 else []
            return RiskSignal("anomaly_detection", score, 0.75 if score >= 60 else 0.55, evidence)

        failed = self._failed_login_count(event, text_lower)
        ports = self._suspicious_ports(event, text_lower)
        anomaly_terms = [
            "abnormal", "unusual", "impossible travel", "after hours", "off-hours",
            "new country", "new device", "unusual access time", "suspicious login",
            "malware", "rootkit", "backdoor", "ransomware", "known malicious",
        ]
        evidence: List[str] = []
        score = 10.0
        if failed >= 5:
            score = max(score, min(90, 30 + failed * 8))
            evidence.append("Authentication volume is anomalous for normal behavior")
        if ports:
            score = max(score, 68)
            evidence.append("Network behavior includes unusual port(s)")
        if any(term in text_lower for term in anomaly_terms):
            score = max(score, 70)
            evidence.append("Anomalous or malicious behavior indicator compared with baseline")
        return RiskSignal("anomaly_detection", score, 0.62 if evidence else 0.45, evidence, active=True)

    def _threat_intel_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        ti = event.get("threat_intelligence") or event.get("threat_intel") or event.get("ti") or event.get("intel")
        if not isinstance(ti, Mapping):
            # Also support flattened lookup responses from Vrin_TI.
            ti_keys = {"malicious", "malicious_found", "known_bad", "threat_score", "reputation", "sources", "sightings"}
            if any(key in event for key in ti_keys):
                ti = event
            else:
                return RiskSignal("threat_intelligence", 0, 0.0, [], active=False)

        evidence: List[str] = []
        score = 0.0
        confidence = self._confidence_value(ti.get("confidence"), default=0.55)
        if bool(ti.get("malicious")) or bool(ti.get("malicious_found")) or bool(ti.get("known_bad")):
            score = max(score, 92)
            evidence.append("Indicator matched known malicious threat intelligence")
        reputation = str(ti.get("reputation") or ti.get("classification") or "").lower()
        if reputation in {"malicious", "known_bad", "bad"}:
            score = max(score, 92)
            evidence.append("Threat-intelligence reputation is malicious")
        elif reputation in {"suspicious", "medium", "high"}:
            score = max(score, 65)
            evidence.append("Threat-intelligence reputation is suspicious")

        threat_score = ti.get("threat_score") or ti.get("risk_score") or ti.get("score")
        if threat_score is not None:
            normalized = self._score_from_fraction_or_percent(threat_score)
            score = max(score, normalized)
            evidence.append(f"Threat-intelligence score {normalized:.0f}/100")

        sources = ti.get("sources") or ti.get("feeds") or []
        if isinstance(sources, str):
            sources = [sources]
        source_count = len(sources) if isinstance(sources, Iterable) else 0
        if source_count >= 2:
            score = min(100, max(score, 60) + min(12, source_count * 3))
            confidence = min(0.95, confidence + min(0.20, source_count * 0.04))
            evidence.append(f"Threat intelligence corroborated by {source_count} source(s)")

        sightings = ti.get("sightings") or ti.get("sighting_count") or 0
        if isinstance(sightings, list):
            sighting_count = len(sightings)
        else:
            try:
                sighting_count = int(float(sightings))
            except (TypeError, ValueError):
                sighting_count = 0
        if sighting_count:
            score = max(score, min(85, 35 + sighting_count * 7))
            evidence.append(f"Indicator has {sighting_count} threat-intelligence sighting(s)")

        if not evidence:
            return RiskSignal("threat_intelligence", 0, confidence, [], active=False)
        return RiskSignal("threat_intelligence", min(score, 100), confidence, evidence)

    def _behavior_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        evidence: List[str] = []
        score = 0.0
        behavior = event.get("behavior") if isinstance(event.get("behavior"), Mapping) else {}
        auth = event.get("authentication") if isinstance(event.get("authentication"), Mapping) else {}
        user_behavior = event.get("user_behavior") if isinstance(event.get("user_behavior"), Mapping) else {}

        failed = self._failed_login_count(event, text_lower)
        if failed >= 5:
            score = max(score, min(88, 35 + failed * 7))
            evidence.append(f"Behavioral analysis: repeated failed logins ({failed})")
        if bool(behavior.get("abnormal_access_time")) or bool(user_behavior.get("abnormal_access_time")):
            score = max(score, 65)
            evidence.append("Abnormal access time for user/system")
        if bool(behavior.get("impossible_travel")) or bool(user_behavior.get("impossible_travel")):
            score = max(score, 78)
            evidence.append("Impossible-travel/new-location login behavior")
        if bool(auth.get("privilege_escalation")) or "privilege escalation" in text_lower:
            score = max(score, 78)
            evidence.append("Privilege escalation behavior observed")
        if any(term in text_lower for term in ["abnormal access time", "off-hours login", "new device", "new geo", "unusual login behavior"]):
            score = max(score, 65)
            evidence.append("Suspicious login behavior detected")

        if not evidence:
            return RiskSignal("behavioral_analysis", 0, 0.0, [], active=False)
        return RiskSignal("behavioral_analysis", score, 0.70, evidence)

    def _siem_correlation_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        evidence: List[str] = []
        score = 0.0
        correlated = event.get("correlated_alerts") or event.get("correlated_events")
        count = 0
        if isinstance(correlated, list):
            count = len(correlated)
        elif isinstance(correlated, (int, float, str)):
            try:
                count = int(float(correlated))
            except (TypeError, ValueError):
                count = 0

        correlation = event.get("correlation") if isinstance(event.get("correlation"), Mapping) else {}
        for key in ["alert_count", "event_count", "number_of_correlated_alerts", "correlated_alert_count"]:
            if key in event:
                count = max(count, self._safe_int(event.get(key)))
            if key in correlation:
                count = max(count, self._safe_int(correlation.get(key)))

        # If a raw SIEM text line contains several alert terms, use it as weak
        # correlation evidence.
        if not count:
            marker_count = sum(text_lower.count(marker) for marker in [" alert", " failed", " denied", " malware", "rootkit", "blocked"])
            if marker_count >= 3:
                count = marker_count

        if count >= 2:
            score = min(90, 35 + count * 10)
            evidence.append(f"SIEM/log correlation found {count} related alert(s)")

        if correlation.get("same_ip_multiple_events"):
            score = max(score, 65)
            evidence.append("Multiple events correlate to the same source IP")
        if correlation.get("timeline_attack_chain") or "attack chain" in text_lower:
            score = max(score, 78)
            evidence.append("Correlated timeline suggests an attack chain")

        if not evidence:
            return RiskSignal("siem_log_correlation", 0, 0.0, [], active=False)
        return RiskSignal("siem_log_correlation", score, 0.72, evidence)

    def _ai_reasoning_signal(self, event: Mapping[str, Any], text_lower: str) -> RiskSignal:
        evidence: List[str] = []
        threat_level = str(
            self._first_present(event, "threat_level", "risk_level", "severity") or ""
        ).lower()
        confidence_value = self._confidence_value(self._first_present(event, "confidence", "model_confidence"), default=0.55)
        if threat_level in self.SEVERITY_SCORE:
            score = self.SEVERITY_SCORE[threat_level]
            evidence.append(f"AI/threat-agent reasoning rated the event {threat_level}")
            return RiskSignal("ai_reasoning", score, confidence_value, evidence)

        indicators = event.get("indicators") or event.get("reasons") or []
        if isinstance(indicators, str):
            indicators = [indicators]
        indicator_count = len(indicators) if isinstance(indicators, Iterable) else 0
        if indicator_count >= 2:
            score = min(85, 40 + indicator_count * 10)
            evidence.append(f"AI reasoning found {indicator_count} indicator(s)")
            return RiskSignal("ai_reasoning", score, max(0.60, confidence_value), evidence)

        compound_terms = ["malware", "failed", "known malicious", "unusual", "abnormal", "rootkit", "breach"]
        hits = [term for term in compound_terms if term in text_lower]
        if len(hits) >= 2:
            score = min(82, 38 + len(hits) * 12)
            evidence.append("AI reasoning connected multiple suspicious facts: " + ", ".join(hits[:5]))
            return RiskSignal("ai_reasoning", score, 0.60, evidence)
        return RiskSignal("ai_reasoning", 5, 0.40, [], active=True)

    def _severity_signal(self, event: Mapping[str, Any]) -> RiskSignal:
        severity = self._first_present(event, "severity", "event_severity")
        if severity is None:
            return RiskSignal("declared_severity", 0, 0.0, [], active=False)
        if isinstance(severity, (int, float)):
            score = self._score_from_fraction_or_percent(severity)
            label = f"{score:.0f}/100"
        else:
            label = str(severity).lower()
            score = self.SEVERITY_SCORE.get(label, 20)
        return RiskSignal("declared_severity", score, 0.60, [f"Declared event severity is {label}"])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _risk_level(self, score: int) -> str:
        if score >= 90:
            return "Critical"
        if score >= 70:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    def _confidence_score(self, active: List[RiskSignal], corroborating: List[RiskSignal], event: Mapping[str, Any]) -> int:
        if not active:
            return 0
        total_weight = sum(self.LAYER_WEIGHTS.get(s.layer, 0.05) for s in active) or 1.0
        weighted_conf = sum(
            s.confidence * self.LAYER_WEIGHTS.get(s.layer, 0.05) for s in active
        ) / total_weight
        diversity_bonus = min(0.25, max(0, len(corroborating) - 1) * 0.07)
        analyst_history_bonus = 0.0
        if event.get("historically_validated") or event.get("validated_by_analyst"):
            analyst_history_bonus = 0.10
        value = (weighted_conf + diversity_bonus + analyst_history_bonus) * 100
        return int(round(max(0.0, min(100.0, value))))

    def _confidence_label(self, score: int) -> str:
        if score >= 80:
            return "high"
        if score >= 55:
            return "medium"
        return "low"

    def _requires_human_validation(self, risk_score: int, text_lower: str, event: Mapping[str, Any]) -> bool:
        high_impact_terms = [
            "block ip", "isolate", "quarantine", "kill process", "shutdown",
            "disable account", "contain", "firewall deny", "drop traffic",
        ]
        high_impact = bool(event.get("high_impact") or event.get("requires_human_validation"))
        high_impact = high_impact or any(term in text_lower for term in high_impact_terms)
        return high_impact or risk_score >= 70

    def _recommended_action(self, risk_score: int, requires_human: bool, ip: str) -> str:
        target = "the source" if ip == "unknown" else ip
        if risk_score >= 90:
            return (
                f"Critical risk: page a human analyst, validate evidence, and approve or reject "
                f"temporary containment for {target}; collect forensic context before permanent action."
            )
        if risk_score >= 70:
            if requires_human:
                return (
                    f"High risk: investigate immediately and require analyst validation before blocking, "
                    f"isolating, or killing processes related to {target}."
                )
            return "High risk: investigate immediately and collect more evidence."
        if risk_score >= 40:
            return "Medium risk: alert the SOC, correlate with logs/TI, and monitor; do not auto-contain."
        return "Low risk: log, continue monitoring, and use analyst feedback if new evidence appears."

    def _event_text(self, event: Mapping[str, Any]) -> str:
        parts: List[str] = []

        def walk(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, Mapping):
                for key, child in value.items():
                    parts.append(str(key))
                    walk(child)
            elif isinstance(value, (list, tuple, set)):
                for child in value:
                    walk(child)
            else:
                parts.append(str(value))

        walk(event)
        return " ".join(parts)

    def _first_present(self, mapping: Mapping[str, Any], *keys: str) -> Optional[Any]:
        for key in keys:
            if key in mapping and mapping.get(key) not in (None, ""):
                return mapping.get(key)
        return None

    def _score_from_fraction_or_percent(self, value: Any) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        if math.isnan(number) or math.isinf(number):
            return 0.0
        if 0.0 <= number <= 1.0:
            return number * 100
        return max(0.0, min(100.0, number))

    def _confidence_value(self, value: Any, default: float = 0.50) -> float:
        if value is None:
            return default
        if isinstance(value, str):
            text = value.strip().lower().replace("-", "_").replace(" ", "_")
            if text in self.CONFIDENCE_VALUE:
                return self.CONFIDENCE_VALUE[text]
        return self._score_from_fraction_or_percent(value) / 100.0 if not isinstance(value, str) else default

    def _failed_login_count(self, event: Mapping[str, Any], text_lower: str) -> int:
        candidates: List[Any] = []
        for key in [
            "failed_login_attempts", "failed_login_count", "failed_attempts",
            "auth_failures", "failure_count",
        ]:
            if key in event:
                candidates.append(event.get(key))
        auth = event.get("authentication") if isinstance(event.get("authentication"), Mapping) else {}
        for key in ["failed_login_count", "failed_attempts", "failures"]:
            if key in auth:
                candidates.append(auth.get(key))
        count = max([self._safe_int(v) for v in candidates] or [0])
        for match in re.findall(r"(\d+)\s+(?:failed|failure|failures|failed\s+login|failed\s+password)", text_lower):
            count = max(count, self._safe_int(match))
        if "failed login" in text_lower or "failed password" in text_lower:
            count = max(count, len(re.findall(r"failed\s+(?:login|password)", text_lower)) or text_lower.count("failed"))
        return count

    def _suspicious_ports(self, event: Mapping[str, Any], text_lower: str) -> set[int]:
        ports: set[int] = set()
        for key in ["port", "dest_port", "destination_port", "source_port"]:
            if key in event:
                value = self._safe_int(event.get(key))
                if value in self.SUSPICIOUS_PORTS:
                    ports.add(value)
        for key in ["ports", "suspicious_ports"]:
            raw = event.get(key)
            if isinstance(raw, (list, tuple, set)):
                for p in raw:
                    value = self._safe_int(p)
                    if value in self.SUSPICIOUS_PORTS:
                        ports.add(value)
        network = event.get("network") if isinstance(event.get("network"), Mapping) else {}
        raw_ports = network.get("ports") if isinstance(network.get("ports"), list) else []
        for p in raw_ports:
            value = self._safe_int(p)
            if value in self.SUSPICIOUS_PORTS:
                ports.add(value)
        for match in re.findall(r"(?::|port\s+)(4444|5555|6666|1337|31337|31338|8081)\b", text_lower):
            ports.add(int(match))
        if "unusual port" in text_lower or "suspicious port" in text_lower:
            ports.add(4444)
        return ports

    def _safe_int(self, value: Any) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    def _dedupe_reason(self, reasons: List[str]) -> List[str]:
        seen = set()
        result = []
        for reason in reasons:
            clean = re.sub(r"\s+", " ", str(reason).strip())
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
        return result


risk_scoring = RiskScoring()
