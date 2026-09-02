"""Vrindha AI — Anti-Hallucination & Evidence-Grounded Security Analysis.

This module implements the Vrindha AI operating contract (:data:`VRINDHA_AI_PROMPT`)
as a deterministic, auditable engine. It is deliberately *not* a free-text
generator: every number and every claim is derived from the event's stored
evidence sections, so the output is reproducible, explainable, and traceable.

Contract highlights (see ``docs/ANTI_HALLUCINATION.md`` for the full mapping):

* Rule 1  — Never fabricate. Each statement is classified as FACT, INFERENCE,
  or UNKNOWN; missing evidence yields
  ``"Insufficient evidence — further investigation required."``
* Rule 2  — Evidence-first order: tool data → raw evidence → validation →
  threat intelligence → rules/correlation → reasoning → risk+confidence →
  human verification → controlled response.
* Rule 4  — TI verification: retrieve, verify source, check freshness, compare
  the IOC with the observed event. No supporting intelligence ⇒
  ``NOT CONFIRMED``; unavailable service ⇒ ``UNKNOWN``. No reputation is
  invented in either case.
* Rule 5  — Every important finding is split into FACT / EVIDENCE /
  INFERENCE / UNKNOWN / RECOMMENDATION (:class:`ClassifiedFinding`).
* Rule 6  — Multi-source correlation: independent signals (rules, auth
  behavior, network behavior, anomaly, TI, correlation, severity, history)
  corroborate each other and raise confidence.
* Rule 7  — Risk 0–100, Confidence 0–100, Severity LOW/MEDIUM/HIGH/CRITICAL.
  Confidence is computed, never "felt".
* Rule 8  — Conflicting evidence ⇒ no forced conclusion, confidence lowered.
* Rule 9  — Structured ``[SECURITY ANALYSIS]`` report (see
  :func:`render_report`).
* Rule 10 — High-impact actions are *recommended*, never executed; execution
  requires policy validation + human approval + controlled execution
  (Commander → Ethics → human → automation).
* Rule 11 — Low confidence or high impact ⇒ "Human verification required."
* Rule 12 — Analyst decisions are recorded in ``analysis_feedback``
  (append-only) and linked back to the audit row.
* Rule 13 — Every analysis persists a full audit row (``evidence_audit``):
  alert id, timestamp, raw evidence, tools used, TI sources, rules triggered,
  correlation results, AI assessment, risk, confidence, recommended action,
  human decision, final action.

Final operating principle:

    "Evidence before inference. Inference before action.
     Verification before high-impact action."
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import (
    ClassifiedFinding,
    EventMode,
    SecurityAnalysis,
    SecurityEvent,
    ThreatIntelStatus,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# The operating contract, verbatim. Served by GET /analysis/prompt and
# referenced by tests so the agent's rules are themselves auditable.
# ---------------------------------------------------------------------------
VRINDHA_AI_PROMPT = """\
Vrindha AI — Anti-Hallucination & Evidence-Grounded Security Agent Prompt

You are Vrindha AI, an AI-powered cybersecurity and SOC assistant.

Your primary objective is to analyze security events accurately while preventing hallucinations, unsupported claims, and unsafe conclusions.

1. CORE RULE

Never invent, assume, or fabricate cybersecurity evidence.

The AI must distinguish between:

- FACT — Directly confirmed by security tools, logs, databases, or verified Threat Intelligence.
- INFERENCE — A reasonable conclusion derived from available evidence.
- UNKNOWN — Information that cannot currently be verified.

If evidence is insufficient, explicitly say:

«"Insufficient evidence — further investigation required."»

Never fill missing information with assumptions.

---

2. EVIDENCE-FIRST ANALYSIS

Always follow this order:

Security Tool Data
        ↓
Raw Evidence
        ↓
Evidence Validation
        ↓
Threat Intelligence
        ↓
Rules / Correlation
        ↓
AI Reasoning
        ↓
Risk + Confidence
        ↓
Human Verification
        ↓
Controlled Response

The LLM must reason from evidence, not from its general knowledge.

---

3. NEVER MAKE UNSUPPORTED CLAIMS

Example:

Input:

IP: 192.168.1.50
37 failed SSH attempts
No verified malicious TI record

Do NOT say:

«"192.168.1.50 is part of a ransomware campaign."»

Instead say:

«"The IP generated suspicious SSH activity consistent with possible brute-force behavior. No verified evidence currently links the IP to a ransomware campaign."»

---

4. VERIFY THREAT INTELLIGENCE

When Threat Intelligence is available:

1. Retrieve the actual IOC information.
2. Verify the source.
3. Check the timestamp/freshness.
4. Compare the IOC with the observed event.
5. Use only information supported by the retrieved intelligence.

If no supporting intelligence exists:

Threat Intelligence Status: NOT CONFIRMED

Do not create a malicious reputation.

---

5. SEPARATE FACT FROM INTERPRETATION

For every important finding, internally classify information as:

FACT:
What was actually observed?

EVIDENCE:
Which log, tool, rule, or TI record supports it?

INFERENCE:
What does the evidence reasonably indicate?

UNKNOWN:
What cannot currently be established?

RECOMMENDATION:
What should the analyst investigate next?

Never present an inference as a confirmed fact.

---

6. USE MULTI-SOURCE CORRELATION

Do not rely on a single signal whenever additional evidence is available.

Correlate:

- SIEM logs
- Network traffic
- Authentication events
- Endpoint telemetry
- Threat Intelligence
- Firewall events
- IDS/IPS alerts
- File/hash information
- User behavior
- Historical activity
- Detection rules

The more independent evidence supports a finding, the higher its confidence can become.

---

7. RISK SCORE

Do not make security decisions using only:

Malicious = TRUE/FALSE

Generate:

Risk Score: 0–100
Confidence: 0–100
Severity: LOW / MEDIUM / HIGH / CRITICAL

Consider:

- Evidence strength
- Number of correlated indicators
- Threat Intelligence confidence
- Attack severity
- Asset importance
- Behavioral abnormality
- Historical evidence
- Detection-rule confidence

Do not artificially increase confidence simply because the LLM "feels certain."

---

8. UNCERTAINTY HANDLING

If evidence conflicts:

Evidence Conflict Detected
        ↓
Do not force a conclusion
        ↓
Explain the conflicting evidence
        ↓
Lower confidence
        ↓
Request further investigation

Use phrases such as:

«"Evidence is conflicting."»

«"This behavior is suspicious but not conclusively malicious."»

«"Current evidence is insufficient to confirm the attribution."»

---

9. STRUCTURED OUTPUT

Every security analysis should follow this format:

[SECURITY ANALYSIS]

Event:
<what happened>

FACTS:
- <verified fact>
- <verified fact>

EVIDENCE:
- <security log/tool evidence>
- <Threat Intelligence evidence>

DETECTION:
<rule, anomaly, behavioral pattern, or correlation>

ASSESSMENT:
<AI interpretation based only on available evidence>

RISK SCORE:
<0–100>

CONFIDENCE:
<0–100>

THREAT INTELLIGENCE:
CONFIRMED / NOT CONFIRMED / UNKNOWN

UNKNOWN INFORMATION:
<missing evidence>

RECOMMENDED ACTION:
<safest appropriate investigation or defensive action>

HUMAN APPROVAL:
REQUIRED / NOT REQUIRED

REASON:
<why>

---

10. HIGH-IMPACT ACTION PROTECTION

The AI must NOT independently perform high-impact actions unless an explicitly configured security policy authorizes autonomous execution.

Examples:

- Blocking IP addresses
- Disabling accounts
- Isolating machines
- Modifying firewall rules
- Deleting files
- Killing processes
- Changing security configurations

For high-impact actions:

AI Recommendation
        ↓
Policy Validation
        ↓
Human Approval
        ↓
Controlled Execution

---

11. HUMAN-IN-THE-LOOP

Human analysts remain the final authority for uncertain or high-impact decisions.

If confidence is low or the potential impact is high:

DO NOT EXECUTE

Instead:

«"Human verification required."»

---

12. FEEDBACK LOOP

When an analyst confirms or rejects an alert, record the result:

AI Finding
↓
Analyst Decision
↓
True Positive / False Positive / False Negative
↓
Feedback Database
↓
Rule / Detection Improvement

Use feedback to improve future detection.

Do not silently change historical evidence or audit records.

---

13. AUDITABILITY

For every important AI decision, preserve:

Alert ID
Timestamp
Raw Evidence
Tools Used
Threat Intelligence Sources
Rules Triggered
Correlation Results
AI Assessment
Risk Score
Confidence
Recommended Action
Human Decision
Final Action

Every conclusion must be traceable back to evidence.

---

FINAL OPERATING PRINCIPLE

Follow this rule at all times:

«"Evidence before inference. Inference before action. Verification before high-impact action."»

Never say:

«"Trust me, this is malicious."»

Instead say:

«"Here is the evidence, here is what it indicates, here is the confidence level, here is what remains unknown, and here is the recommended next step."»

Your purpose is not to claim that you detect every attack.

Your purpose is to assist SOC analysts by collecting evidence, correlating security signals, analyzing threats, assigning explainable risk, identifying uncertainty, and recommending safe defensive actions.
"""

# ---------------------------------------------------------------------------
# Canonical phrases (contract rule 1 / rule 8 / rule 11)
# ---------------------------------------------------------------------------
INSUFFICIENT_EVIDENCE_PHRASE = "Insufficient evidence — further investigation required."
CONFLICT_PHRASE = "Evidence is conflicting."
SUSPICIOUS_NOT_CONCLUSIVE_PHRASE = "This behavior is suspicious but not conclusively malicious."
ATTRIBUTION_UNVERIFIED_PHRASE = "Current evidence is insufficient to confirm the attribution."
#: The contract's rule-11 phrase (without the terminal period so it composes
#: cleanly mid-sentence; usage that ends a sentence appends the period).
HUMAN_VERIFICATION_PHRASE = "Human verification required"

#: The exact canonical sentence for the contract's own example (rule 3).
BRUTE_FORCE_UNCONFIRMED_SENTENCE = (
    "No verified evidence currently links the IP to a ransomware campaign."
)

#: Actions that are high-impact and may never be executed by the AI alone
#: (contract rule 10). The analyzer only ever *recommends* these.
HIGH_IMPACT_ACTIONS = {
    "block_ip",
    "disable_account",
    "isolate_host",
    "quarantine_host",
    "modify_firewall",
    "firewall_change",
    "delete_files",
    "kill_process",
    "change_security_configuration",
}

#: Terms that must never appear in an assessment unless TI is CONFIRMED.
#: The engine generates text deterministically, but this guard also protects
#: any future LLM integration that reuses the same report pipeline.
FORBIDDEN_WITHOUT_TI = (
    "part of a ransomware campaign",
    "confirmed malicious",
    "definitely malicious",
    "trust me",
    "malware infection confirmed",
    "data was exfiltrated",
    "exfiltrated data",
    "apt group",
    "botnet member",
    "c2 channel confirmed",
    "backdoor installed",
    "host is compromised by",
    "will attack",
)

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 31338, 8081}

SEVERITY_SCORE = {"low": 20, "medium": 50, "high": 78, "critical": 93}

#: Relative weight of each independent evidence layer (contract rule 7).
SIGNAL_WEIGHTS: Dict[str, float] = {
    "rule_detection": 0.20,
    "authentication_behavior": 0.20,
    "threat_intelligence": 0.18,
    "network_behavior": 0.15,
    "anomaly_detection": 0.12,
    "correlation": 0.08,
    "declared_severity": 0.04,
    "historical_activity": 0.03,
}

#: Freshness windows for threat-intelligence verification (contract rule 4).
TI_FRESHNESS_HOURS = 24        # enrichment batch must be this fresh vs. the event
TI_RECORD_MAX_AGE_DAYS = 180   # a record's own last_seen/observed_at must be within

RULE_KEYWORDS: List[Tuple[Tuple[str, ...], int, str]] = [
    (("ransomware", "rootkit", "backdoor"), 90, "high-severity malware/rootkit/backdoor indicator"),
    (("malware", "trojan", "worm", "botnet"), 78, "malware indicator keyword"),
    (("credential stuffing", "brute force", "brute-force", "password spray"), 68,
     "credential-attack pattern keyword"),
    (("exploit", "intrusion", "breach"), 62, "exploit/intrusion/breach keyword"),
    (("phishing", "ddos", "data exfiltration", "exfiltration"), 58, "known attack-technique keyword"),
    (("attack", "unauthorized"), 45, "attack/unauthorized-access keyword"),
]

_FAILED_RE = re.compile(r"(\d+)\s+failed\s+(?:\w+\s+){0,2}(?:logins?|passwords?|attempts?|auth\w*)?")
_FEEDBACK_DECISIONS = {"true_positive", "false_positive", "insufficient_evidence", "unknown"}

ENGINE_VERSION = "evidence-grounded-analysis-v1"


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(v) for v in value)
    return str(value) if value is not None else ""


def _safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _severity_label(risk: int) -> str:
    if risk >= 90:
        return "critical"
    if risk >= 70:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def enforce_claim_guard(assessment: str, ti_status: "ThreatIntelStatus | str") -> Tuple[str, bool]:
    """Rule 3 safety net: strip attribution claims that TI does not support.

    Returns ``(sanitized_assessment, triggered)``. Triggered means the input
    contained a forbidden claim without verified threat intelligence; the
    offending sentence is replaced with the canonical unverified wording.
    """
    status = ThreatIntelStatus(ti_status) if not isinstance(ti_status, ThreatIntelStatus) else ti_status
    if status == ThreatIntelStatus.CONFIRMED:
        return assessment, False
    triggered = False
    sentences: List[str] = []
    for raw in re.split(r"(?<=[.!?])\s+", assessment.strip()):
        lowered = raw.lower()
        if any(term in lowered for term in FORBIDDEN_WITHOUT_TI):
            triggered = True
            continue
        sentences.append(raw)
    if triggered and not sentences:
        sentences = [ATTRIBUTION_UNVERIFIED_PHRASE]
    return " ".join(sentences), triggered


def render_report(analysis: SecurityAnalysis) -> str:
    """Render the structured ``[SECURITY ANALYSIS]`` report (contract rule 9)."""
    ti_label = analysis.threat_intelligence.value.replace("_", " ").upper()
    facts = "\n".join(f"- {f}" for f in analysis.facts) or "- none recorded"
    evidence = "\n".join(f"- {e}" for e in analysis.evidence) or "- none recorded"
    unknown = "\n".join(f"- {u}" for u in analysis.unknown_information) or "- none identified"
    return (
        "[SECURITY ANALYSIS]\n\n"
        f"Event:\n{analysis.event}\n\n"
        f"FACTS:\n{facts}\n\n"
        f"EVIDENCE:\n{evidence}\n\n"
        f"DETECTION:\n{analysis.detection}\n\n"
        f"ASSESSMENT:\n{analysis.assessment}\n\n"
        f"RISK SCORE:\n{analysis.risk_score}\n\n"
        f"CONFIDENCE:\n{analysis.confidence}\n\n"
        f"THREAT INTELLIGENCE:\n{ti_label}\n\n"
        f"UNKNOWN INFORMATION:\n{unknown}\n\n"
        f"RECOMMENDED ACTION:\n{analysis.recommended_action}\n\n"
        f"HUMAN APPROVAL:\n{'REQUIRED' if analysis.human_approval_required else 'NOT REQUIRED'}\n\n"
        f"REASON:\n{analysis.reason}\n"
    )


# ---------------------------------------------------------------------------
# Persistence (auditability, contract rule 13; feedback, contract rule 12)
# ---------------------------------------------------------------------------
def _db():
    from vrin_SOC.database import db

    return db


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT UNIQUE,
            event_id TEXT,
            correlation_id TEXT,
            timestamp TEXT,
            raw_evidence TEXT,
            tools_used TEXT,
            ti_sources TEXT,
            rules_triggered TEXT,
            correlation_results TEXT,
            ai_assessment TEXT,
            risk_score INTEGER,
            confidence INTEGER,
            severity TEXT,
            threat_intelligence TEXT,
            recommended_action TEXT,
            human_decision TEXT,
            final_action TEXT,
            report TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT,
            analyst TEXT,
            decision TEXT,
            notes TEXT,
            recorded_at TEXT
        )
        """
    )


class VrindhaAI(BaseAgent):
    """Vrindha AI — evidence-grounded, anti-hallucination security analysis.

    The agent analyzes one :class:`SecurityEvent` at a time and produces a
    :class:`SecurityAnalysis` (plus its rendered report). It never executes
    defensive actions; high-impact recommendations are parked for human
    approval through the existing Commander → Ethics → human chain.
    """

    name = "VrindhaAI"
    kind = "analyzer"
    capabilities = [
        "evidence_analysis",
        "fact_inference_separation",
        "threat_intelligence_verification",
        "risk_confidence_scoring",
        "structured_report",
        "audit",
        "feedback",
    ]
    agent_version = "1.0"

    def __init__(self, bus: Optional[EventBus] = None) -> None:
        super().__init__(bus)
        db = _db()
        db._run_db(_ensure_tables)  # noqa: SLF001 — schema bootstrap, idempotent

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def prompt(self) -> Dict[str, Any]:
        """The verbatim operating contract (auditable agent rules)."""
        return {
            "status": "success",
            "agent": self.name,
            "engine": ENGINE_VERSION,
            "deterministic": True,
            "rules": 13,
            "prompt": VRINDHA_AI_PROMPT,
        }

    def analyze(self, event: SecurityEvent) -> SecurityAnalysis:
        """Run the full evidence-grounded analysis and persist the audit row."""
        return self.run_guarded(self._analyze, event)  # type: ignore[return-value]

    def record_feedback(
        self,
        analysis_id: str,
        analyst: str,
        decision: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Rule 12: record an analyst decision; never rewrite history.

        The audit row's ``human_decision`` / ``final_action`` columns are the
        only mutable fields (they are the contract's "Human Decision" and
        "Final Action"). Every decision is additionally appended to
        ``analysis_feedback`` so the feedback database is append-only.
        """
        if decision not in _FEEDBACK_DECISIONS:
            return {
                "status": "error",
                "reason": f"decision must be one of {sorted(_FEEDBACK_DECISIONS)}",
            }
        if not analyst:
            return {"status": "error", "reason": "analyst identity is required (human accountability)"}

        db = _db()

        def transaction(conn):
            row = conn.execute(
                "SELECT analysis_id, recommended_action FROM evidence_audit WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                return None
            recommended = row[1] or ""
            final_action = f"{decision}: {recommended}" if recommended else decision
            conn.execute(
                "UPDATE evidence_audit SET human_decision = ?, final_action = ? WHERE analysis_id = ?",
                (decision, final_action, analysis_id),
            )
            conn.execute(
                "INSERT INTO analysis_feedback (analysis_id, analyst, decision, notes, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (analysis_id, analyst, decision, notes[:2000], utc_now_iso()),
            )
            return decision

        try:
            result = db._run_db(transaction)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(str(exc))
            return {"status": "error", "reason": str(exc)[:256]}
        if result is None:
            return {"status": "error", "reason": f"analysis {analysis_id} not found"}
        self._after(self._before(), ok=True)
        return {
            "status": "success",
            "analysis_id": analysis_id,
            "analyst": analyst,
            "decision": result,
            "note": "Feedback recorded; audit row updated with the human decision (append-only feedback).",
        }

    def get_audit(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Rule 13: the full preserved record for one analysis."""
        db = _db()

        def query(conn):
            row = conn.execute(
                "SELECT analysis_id, event_id, correlation_id, timestamp, raw_evidence, tools_used, "
                "ti_sources, rules_triggered, correlation_results, ai_assessment, risk_score, "
                "confidence, severity, threat_intelligence, recommended_action, human_decision, "
                "final_action, report, created_at FROM evidence_audit WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            return row

        try:
            row = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(str(exc))
            return None
        if row is None:
            return None
        return self._row_to_record(row)

    def list_audit(self, limit: int = 50) -> Dict[str, Any]:
        db = _db()

        def query(conn):
            return conn.execute(
                "SELECT analysis_id, event_id, timestamp, risk_score, confidence, severity, "
                "threat_intelligence, recommended_action, human_decision FROM evidence_audit "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "count": len(rows),
            "records": [
                {
                    "analysis_id": r[0], "event_id": r[1], "timestamp": r[2],
                    "risk_score": r[3], "confidence": r[4], "severity": r[5],
                    "threat_intelligence": r[6], "recommended_action": r[7],
                    "human_decision": r[8],
                }
                for r in rows
            ],
        }

    def list_feedback(self, limit: int = 50) -> Dict[str, Any]:
        db = _db()

        def query(conn):
            return conn.execute(
                "SELECT analysis_id, analyst, decision, notes, recorded_at FROM analysis_feedback "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "count": len(rows),
            "feedback": [
                {"analysis_id": r[0], "analyst": r[1], "decision": r[2],
                 "notes": r[3], "recorded_at": r[4]}
                for r in rows
            ],
        }

    # ------------------------------------------------------------------
    # Analysis pipeline (contract rule 2 order)
    # ------------------------------------------------------------------
    def _analyze(self, event: SecurityEvent) -> SecurityAnalysis:
        text = (_flatten(event.data) + " " + (event.event_type or "")).lower()

        # 1) Security tool data / raw evidence → independent signals
        signals = self._extract_signals(event, text)

        # 2) Threat intelligence verification (rule 4)
        ti = self._verify_threat_intelligence(event, signals, text)
        signals = self._merge_ti_signal(signals, ti)

        # 3) Rules / correlation already reflected in signals.
        conflicts = self._detect_conflicts(event, signals, ti)
        conflicting = bool(conflicts)

        # 4) Risk + confidence (rule 7) — computed, never "felt"
        insufficient = self._is_insufficient(signals, ti)
        risk = self._compute_risk(signals, ti, conflicting, insufficient)
        confidence = self._compute_confidence(signals, ti, conflicting, insufficient)
        severity = _severity_label(risk)

        # 5) Fact / inference separation (rule 5) + report sections
        findings = self._build_findings(event, signals, ti, conflicting, insufficient)
        facts, evidence_refs = self._build_facts_and_evidence(event, signals, ti)
        detection = self._build_detection(event, signals)
        assessment = self._build_assessment(event, signals, ti, conflicting, insufficient, risk)

        # 6) Claim guard (rule 3) — last line of defense before output
        assessment, guard_triggered = enforce_claim_guard(assessment, ti["status"])

        # 7) Recommendation + human-approval gate (rules 10/11) — never execution
        recommendation = self._recommend(event, risk, confidence, ti, insufficient, signals)
        human_required, reason = self._human_approval_decision(
            recommendation, risk, confidence, severity
        )

        unknown_information = self._unknown_information(event, signals, ti, conflicting)

        analysis = SecurityAnalysis(
            event_id=event.event_id,
            correlation_id=event.correlation_id,
            event=self._event_description(event),
            facts=facts,
            evidence=evidence_refs,
            findings=findings,
            detection=detection,
            assessment=assessment,
            risk_score=risk,
            confidence=confidence,
            severity=severity,
            threat_intelligence=ti["status"],
            ti_detail={k: v for k, v in ti.items() if k != "status"},
            unknown_information=unknown_information,
            recommended_action=self._recommendation_text(recommendation),
            action_impact=recommendation["impact"],
            human_approval_required=human_required,
            reason=reason,
            evidence_conflicting=conflicting,
            insufficient_evidence=insufficient,
            claim_guard_triggered=guard_triggered,
            signals=[{k: s[k] for k in ("layer", "score", "confidence", "facts", "evidence")}
                     for s in signals],
            mode=event.provenance.mode,
        )

        # 8) Auditability (rule 13) — persist before returning.
        self._persist_audit(event, analysis, ti, recommendation)
        return analysis

    # ------------------------------------------------------------------
    # Signal extraction (rule 6 — multi-source, independent layers)
    # ------------------------------------------------------------------
    def _extract_signals(self, event: SecurityEvent, text: str) -> List[Dict[str, Any]]:
        signals: List[Dict[str, Any]] = []
        data = event.data if isinstance(event.data, dict) else {}

        # -- rule / detection signal -------------------------------------
        rule_score, rule_facts, rule_evidence = self._rule_signal(data, text)
        if rule_score >= 20:
            signals.append(self._signal("rule_detection", rule_score, 0.78,
                                        rule_facts, rule_evidence))

        # -- authentication behavior --------------------------------------
        failed = self._failed_login_count(data, text)
        ssh = "ssh" in text
        if failed > 0:
            score = min(88, 25 + failed * 7)
            signals.append(self._signal(
                "authentication_behavior", score, 0.72,
                facts=[f"{failed} failed authentication attempt(s) recorded"
                       + (" over SSH" if ssh else "")],
                evidence=["authentication telemetry (event.data.authentication)"],
            ))

        # -- network behavior ---------------------------------------------
        net_score, net_facts, net_evidence = self._network_signal(data, text)
        if net_score >= 20:
            signals.append(self._signal("network_behavior", net_score, 0.68,
                                        net_facts, net_evidence))

        # -- anomaly detection (Data Science AI output) --------------------
        anomaly = (event.analysis or {}).get("anomaly") if isinstance(event.analysis, dict) else None
        if isinstance(anomaly, dict):
            a_score = self._frac(anomaly.get("anomaly_score"))
            if a_score >= 30 or anomaly.get("is_anomaly"):
                facts = [f"anomaly detector scored {a_score:.0f}/100 "
                         f"(is_anomaly={bool(anomaly.get('is_anomaly'))})"]
                ev = ["Data Science anomaly engine (event.analysis.anomaly)"]
                model = anomaly.get("model")
                if model:
                    ev.append(f"model: {model} {anomaly.get('model_version', '')}".strip())
                signals.append(self._signal("anomaly_detection", min(a_score, 100),
                                            0.75 if a_score >= 60 else 0.55, facts, ev))

        # -- correlation (SOC Analyst AI / event.correlation) ---------------
        corr_count = self._correlated_count(event)
        if corr_count >= 1:
            score = min(80, 35 + corr_count * 10)
            signals.append(self._signal(
                "correlation", score, 0.72,
                facts=[f"{corr_count} related event(s) in the correlation window"],
                evidence=["event.correlation (SOC Analyst AI)"],
            ))

        # -- declared severity (source system) ------------------------------
        # A label from the source system, not independent evidence: it keeps
        # its small weight in scoring but never counts as corroboration.
        sev = (event.severity or "low").lower()
        if sev in SEVERITY_SCORE and sev != "low":
            signals.append(self._signal(
                "declared_severity", SEVERITY_SCORE[sev], 0.6,
                facts=[f"source system declared severity {sev}"],
                evidence=["event.severity (source-system label — not independent evidence)"],
            ))

        # -- historical activity --------------------------------------------
        history = _safe_int(data.get("historical_alerts") or data.get("historical_count"))
        if history >= 1:
            signals.append(self._signal(
                "historical_activity", min(70, 25 + history * 10), 0.65,
                facts=[f"{history} prior alert(s) for this entity on record"],
                evidence=["historical activity store (event.data)"],
            ))

        return signals

    def _rule_signal(self, data: Dict[str, Any], text: str) -> Tuple[float, List[str], List[str]]:
        facts: List[str] = []
        evidence: List[str] = []
        score = 0.0
        declared = data.get("detection") or data.get("rules_triggered")
        if isinstance(declared, str):
            declared = [declared]
        if isinstance(declared, (list, tuple)):
            for rule in declared:
                rule = str(rule)
                if rule.strip():
                    score = max(score, 75)
                    facts.append(f"detection rule triggered: {rule}")
                    evidence.append("detection rule record (event.data.detection / rules_triggered)")
        for keywords, value, reason in RULE_KEYWORDS:
            if any(k in text for k in keywords):
                score = max(score, value)
                facts.append(reason)
                evidence.append("keyword rule set (RULE_KEYWORDS)")
        failed = self._failed_login_count(data, text)
        if failed >= 5:
            score = max(score, min(80, 20 + failed * 8))
            facts.append(f"failed-authentication threshold exceeded ({failed})")
            evidence.append("authentication telemetry (event.data.authentication)")
        return score, facts, evidence

    def _failed_login_count(self, data: Dict[str, Any], text: str) -> int:
        candidates: List[Any] = []
        for key in ("failed_login_attempts", "failed_login_count", "failed_attempts",
                    "auth_failures", "failure_count"):
            if key in data:
                candidates.append(data.get(key))
        auth = data.get("authentication") if isinstance(data.get("authentication"), dict) else {}
        for key in ("failed_login_count", "failed_attempts", "failures", "auth_failures"):
            if key in auth:
                candidates.append(auth.get(key))
        count = max([_safe_int(v) for v in candidates] or [0])
        for match in _FAILED_RE.findall(text):
            count = max(count, _safe_int(match))
        return count

    def _network_signal(self, data: Dict[str, Any], text: str) -> Tuple[float, List[str], List[str]]:
        facts: List[str] = []
        evidence: List[str] = []
        score = 0.0
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        outbound = network.get("outbound") if isinstance(network.get("outbound"), dict) else {}
        ports: set = set()
        for raw in (network.get("ports"), data.get("ports")):
            if isinstance(raw, (list, tuple)):
                ports.update(_safe_int(p) for p in raw)
        if outbound.get("port"):
            ports.add(_safe_int(outbound.get("port")))
        for p in sorted(ports):
            if p in SUSPICIOUS_PORTS:
                score = max(score, 65)
                facts.append(f"suspicious/unusual port {p} observed")
        if outbound.get("ip"):
            score = max(score, 60)
            facts.append(f"outbound connection to {outbound.get('ip')}"
                         + (f":{outbound.get('port')}" if outbound.get("port") else ""))
        if network.get("unusual_port_count"):
            score = max(score, 55)
            facts.append(f"{network.get('unusual_port_count')} unusual port(s) in use")
        for p in re.findall(r"\b(4444|5555|6666|1337|31337|31338|8081)\b", text):
            if _safe_int(p) in SUSPICIOUS_PORTS and _safe_int(p) not in ports:
                score = max(score, 65)
                facts.append(f"suspicious port {_safe_int(p)} referenced in event text")
        if facts:
            evidence.append("network telemetry (event.data.network)")
        return score, facts, evidence

    @staticmethod
    def _correlated_count(event: SecurityEvent) -> int:
        corr = event.correlation if isinstance(event.correlation, dict) else {}
        count = _safe_int(corr.get("related_count"))
        related = corr.get("related_events")
        if isinstance(related, list):
            count = max(count, len(related))
        data = event.data if isinstance(event.data, dict) else {}
        for key in ("correlated_alerts", "correlated_events"):
            if isinstance(data.get(key), list):
                count = max(count, len(data[key]))
        return count

    @staticmethod
    def _frac(value: Any) -> float:
        number = _safe_float(value)
        if 0.0 <= number <= 1.0:
            return number * 100.0
        return _clamp(number)

    @staticmethod
    def _signal(layer: str, score: float, confidence: float,
                facts: List[str], evidence: List[str]) -> Dict[str, Any]:
        return {
            "layer": layer,
            "score": round(_clamp(score), 2),
            "confidence": round(_clamp(confidence, 0.0, 1.0), 3),
            "facts": [str(f) for f in facts],
            "evidence": [str(e) for e in evidence],
            "status": "active",
        }

    # ------------------------------------------------------------------
    # Threat intelligence verification (rule 4)
    # ------------------------------------------------------------------
    def _verify_threat_intelligence(
        self, event: SecurityEvent, signals: List[Dict[str, Any]], text: str
    ) -> Dict[str, Any]:
        ti = event.threat_intelligence if isinstance(event.threat_intelligence, dict) else {}
        records = self._normalize_ti_records(ti)
        checked_at = _parse_ts(ti.get("checked_at"))
        event_ts = _parse_ts(event.timestamp)

        detail: Dict[str, Any] = {
            "checked": bool(checked_at or records or any(k in ti for k in
                                                         ("malicious", "malicious_found", "sources"))),
            "records_reviewed": len(records),
            "verified_sources": sorted({str(s) for r in records for s in (r.get("sources") or [])}),
            "stale": False,
            "reason": "",
        }

        # (3) Freshness of the enrichment batch.
        if checked_at is not None and event_ts is not None:
            age_hours = (event_ts - checked_at).total_seconds() / 3600.0
            if age_hours > TI_FRESHNESS_HOURS:
                detail["stale"] = True

        # (1)+(2)+(4) Retrieve / verify source / compare with observed event.
        confirmed: List[Dict[str, Any]] = []
        for record in records:
            if record.get("malicious") is not True:
                continue
            sources = [str(s) for s in (record.get("sources") or []) if str(s).strip()]
            if not sources:
                continue  # a record without a verified source is not usable
            seen = _parse_ts(record.get("last_seen") or record.get("observed_at")
                             or record.get("first_seen"))
            if seen is not None and event_ts is not None:
                if (event_ts - seen).total_seconds() / 86400.0 > TI_RECORD_MAX_AGE_DAYS:
                    detail["stale"] = True
                    continue
            if detail["stale"]:
                continue
            observed = (event.entity and event.entity.primary()) or ""
            value = str(record.get("indicator", ""))
            matches = bool(value) and (
                value in text or (observed and (value == observed or value in observed))
            )
            record = dict(record)
            record["sources"] = sources
            record["matches_observed_event"] = matches
            if matches:
                confirmed.append(record)

        if detail["stale"] and records:
            status = ThreatIntelStatus.NOT_CONFIRMED
            detail["reason"] = (
                f"retrieved record(s) exist but exceed the {TI_RECORD_MAX_AGE_DAYS}-day "
                "freshness window — treated as stale, not as supporting intelligence"
            )
        elif confirmed:
            status = ThreatIntelStatus.CONFIRMED
            detail["reason"] = (
                f"{len(confirmed)} verified record(s) match the observed indicator(s) "
                f"with {len(detail['verified_sources'])} source(s)"
            )
        elif ti.get("mode") == "unavailable" or ti.get("status") == "unavailable" or (
            ti.get("degraded") is True and ti.get("found") is None
        ):
            status = ThreatIntelStatus.UNKNOWN
            detail["reason"] = "threat-intelligence service unavailable at analysis time — state cannot be verified"
        elif not detail["checked"]:
            # Rule 4: "If no supporting intelligence exists: NOT CONFIRMED."
            # No check was performed and no supporting intelligence exists —
            # the reputation stays unverified, and nothing is invented.
            status = ThreatIntelStatus.NOT_CONFIRMED
            detail["reason"] = (
                "no supporting intelligence exists (no TI record was checked for this "
                "event) — no malicious reputation is assigned"
            )
        else:
            status = ThreatIntelStatus.NOT_CONFIRMED
            detail["reason"] = (
                "threat intelligence was checked; no verified record supports the observed "
                "indicators — no malicious reputation is assigned"
            )
            if records and not any(r.get("malicious") is True and r.get("sources") for r in records):
                if any(r.get("malicious") is True for r in records):
                    detail["reason"] = (
                        "a record claims malicious status but has no verified source — "
                        "unattributed data is not used to create a reputation"
                    )
                elif any(r.get("indicator") and str(r.get("indicator")) not in text
                         for r in records if r.get("found")):
                    detail["reason"] = "retrieved records do not match the observed event's indicators"

        detail["status"] = status.value
        detail["confirmed_records"] = [
            {"indicator": r.get("indicator"), "sources": r.get("sources"),
             "threat_score": r.get("threat_score"), "matches_observed_event": r.get("matches_observed_event", True)}
            for r in confirmed
        ]
        return detail

    def _normalize_ti_records(self, ti: Dict[str, Any]) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        indicators = ti.get("indicators")
        if isinstance(indicators, list):
            for item in indicators:
                if isinstance(item, dict):
                    records.append({
                        "indicator": item.get("indicator"),
                        "type": item.get("type"),
                        "found": item.get("found"),
                        "malicious": item.get("malicious"),
                        "sources": item.get("sources") or [],
                        "threat_score": item.get("threat_score"),
                        "last_seen": item.get("last_seen") or item.get("observed_at"),
                    })
            if records:
                return records
        # Flat gateway shape: {malicious, sources, threat_score, ...}
        if any(k in ti for k in ("malicious", "malicious_found")):
            records.append({
                "indicator": ti.get("indicator"),
                "type": ti.get("type"),
                "found": ti.get("found", True if ti.get("malicious") else None),
                "malicious": ti.get("malicious", ti.get("malicious_found")),
                "sources": ti.get("sources") or [],
                "threat_score": ti.get("threat_score") or ti.get("score"),
                "last_seen": ti.get("last_seen") or ti.get("observed_at"),
            })
        return records

    def _merge_ti_signal(self, signals: List[Dict[str, Any]], ti: Dict[str, Any]) -> List[Dict[str, Any]]:
        if ti["status"] != ThreatIntelStatus.CONFIRMED:
            return signals  # absence is NOT evidence of safety — no negative signal
        records = ti.get("confirmed_records") or []
        facts = [
            f"verified malicious TI record for {r.get('indicator')} "
            f"(source(s): {', '.join(r.get('sources') or [])})"
            for r in records
        ]
        evidence = ["Threat Intelligence gateway (Vrin_TI / local TI database)"]
        if ti.get("verified_sources"):
            facts.append(f"{len(ti['verified_sources'])} independent TI source(s) corroborate the record")
        signals.append(self._signal("threat_intelligence", 92, 0.9, facts, evidence))
        return signals

    # ------------------------------------------------------------------
    # Conflict + insufficiency (rules 1 and 8)
    # ------------------------------------------------------------------
    def _detect_conflicts(
        self, event: SecurityEvent, signals: List[Dict[str, Any]], ti: Dict[str, Any]
    ) -> List[str]:
        conflicts: List[str] = []
        data = event.data if isinstance(event.data, dict) else {}
        if data.get("conflicting_evidence"):
            conflicts.append("explicit conflicting-evidence flag present in the event data")

        ti_records = self._normalize_ti_records(
            event.threat_intelligence if isinstance(event.threat_intelligence, dict) else {}
        )
        benign = [r for r in ti_records if r.get("found") and r.get("malicious") is False and r.get("sources")]
        strongest = max([s["score"] for s in signals if s["layer"] != "declared_severity"], default=0.0)
        if benign and strongest >= 60:
            conflicts.append(
                "threat intelligence lists the indicator as benign while local detection "
                "signals indicate malicious behavior"
            )
        if ti.get("malicious_found") and any(r.get("malicious") is False and r.get("sources") for r in ti_records):
            conflicts.append("threat intelligence contains both malicious and benign records for the same indicators")

        declared = (event.severity or "low").lower()
        active_scores = [s["score"] for s in signals if s["layer"] != "declared_severity"]
        if declared == "critical" and active_scores and max(active_scores) < 30:
            conflicts.append("declared CRITICAL severity is not supported by the observed signals")
        return conflicts

    def _is_insufficient(self, signals: List[Dict[str, Any]], ti: Dict[str, Any]) -> bool:
        meaningful = [s for s in signals if s["score"] >= 30]
        if ti["status"] == ThreatIntelStatus.CONFIRMED:
            return False
        return len(meaningful) < 2

    # ------------------------------------------------------------------
    # Risk + confidence (rule 7)
    # ------------------------------------------------------------------
    @staticmethod
    def _independent_families(signals: List[Dict[str, Any]]) -> List[str]:
        """Corroboration is only meaningful between *independent* sources.

        The rule-detection layer and the authentication-behavior layer are
        counted as a single family when both are driven by the same
        failed-authentication observations, and a source system's declared
        severity is never independent evidence.
        """
        layers = [s["layer"] for s in signals if s["layer"] != "declared_severity"]
        if "rule_detection" in layers and "authentication_behavior" in layers:
            rule = next(s for s in signals if s["layer"] == "rule_detection")
            auth = next(s for s in signals if s["layer"] == "authentication_behavior")
            if any("failed" in f.lower() for f in rule.get("facts", [])) and auth.get("facts"):
                layers.remove("authentication_behavior")
        return layers

    def _compute_risk(
        self, signals: List[Dict[str, Any]], ti: Dict[str, Any],
        conflicting: bool, insufficient: bool,
    ) -> int:
        active = [s for s in signals if s["status"] == "active"]
        if not active:
            risk = 5.0
        else:
            weight = sum(SIGNAL_WEIGHTS.get(s["layer"], 0.03) for s in active) or 1.0
            risk = sum(s["score"] * SIGNAL_WEIGHTS.get(s["layer"], 0.03) for s in active) / weight
            families = self._independent_families(active)
            family_scores: Dict[str, float] = {}
            for s in active:
                if s["layer"] in families:
                    family_scores[s["layer"]] = max(family_scores.get(s["layer"], 0.0), s["score"])
            corroborating = [f for f, sc in family_scores.items() if sc >= 55]
            strong = [f for f, sc in family_scores.items() if sc >= 75]
            if len(corroborating) >= 2:
                risk += min(8.0, 3.0 * (len(corroborating) - 1))
            if len(strong) >= 3:
                risk += 5.0
        if ti["status"] == ThreatIntelStatus.CONFIRMED:
            risk = max(risk, 85.0)
        if conflicting:
            risk = min(risk, 65.0)  # do not force a high-confidence conclusion
        if insufficient:
            risk = min(risk, 35.0)
        return int(round(_clamp(risk)))

    def _compute_confidence(
        self, signals: List[Dict[str, Any]], ti: Dict[str, Any],
        conflicting: bool, insufficient: bool,
    ) -> int:
        active = [s for s in signals if s["status"] == "active"]
        if not active:
            confidence = 0.10
        else:
            weight = sum(SIGNAL_WEIGHTS.get(s["layer"], 0.03) for s in active) or 1.0
            confidence = sum(s["confidence"] * SIGNAL_WEIGHTS.get(s["layer"], 0.03) for s in active) / weight
            families = self._independent_families(active)
            family_scores: Dict[str, float] = {}
            for s in active:
                if s["layer"] in families:
                    family_scores[s["layer"]] = max(family_scores.get(s["layer"], 0.0), s["score"])
            corroborating = [f for f, sc in family_scores.items() if sc >= 55]
            strong = [f for f, sc in family_scores.items() if sc >= 75]
            if len(corroborating) >= 2:
                confidence += min(0.21, 0.07 * (len(corroborating) - 1))
            if len(strong) >= 3:
                confidence += 0.05
            if ti["status"] == ThreatIntelStatus.CONFIRMED:
                confidence += 0.10
            elif ti["status"] == ThreatIntelStatus.UNKNOWN:
                confidence -= 0.10  # missing corroboration is not "clean"
            elif ti["status"] == ThreatIntelStatus.NOT_CONFIRMED and ti.get("checked"):
                confidence -= 0.05
        if insufficient:
            confidence = min(confidence, 0.35)
        if conflicting:
            confidence = min(confidence * 0.5, 0.40)
        return int(round(_clamp(confidence, 0.0, 0.97) * 100))

    # ------------------------------------------------------------------
    # Report sections (rules 3, 5, 9)
    # ------------------------------------------------------------------
    def _event_description(self, event: SecurityEvent) -> str:
        entity = (event.entity and event.entity.primary()) or "system"
        source = event.source_system or event.source_agent or "unknown source"
        mode_note = "" if event.provenance.mode == EventMode.REAL else \
            f" [data mode: {event.provenance.mode.value.upper()}]"
        return f"{event.event_type} on {entity} at {event.timestamp} (source: {source}){mode_note}"

    def _build_findings(
        self, event: SecurityEvent, signals: List[Dict[str, Any]],
        ti: Dict[str, Any], conflicting: bool, insufficient: bool,
    ) -> List[ClassifiedFinding]:
        findings: List[ClassifiedFinding] = []
        ip = (event.entity and event.entity.ip) or None
        for signal in signals:
            layer = signal["layer"]
            facts, inferences, unknowns, recs = self._finding_parts(layer, signal, ip)
            facts = [f for f in facts if f]
            unknowns = [u for u in unknowns if u]
            recs = [r for r in recs if r]
            if not facts and not inferences:
                continue
            findings.append(ClassifiedFinding(
                fact="; ".join(facts) if facts else "no direct observation recorded for this layer",
                evidence="; ".join(signal.get("evidence") or signal.get("facts") or [])[:200] or "event payload",
                inference="; ".join(inferences) if inferences else "no inference drawn",
                unknown="; ".join(unknowns),
                recommendation="; ".join(recs),
            ))
        return findings

    def _finding_parts(self, layer: str, signal: Dict[str, Any], ip: Optional[str]) -> Tuple[List[str], List[str], List[str], List[str]]:
        facts = list(signal.get("facts") or [])
        if layer == "authentication_behavior":
            return [
                facts,
                ["consistent with possible brute-force behavior"],
                ["no verified TI record links the source to any campaign" if ip else ""],
                ["review authentication logs; require human validation before any block"],
            ]
        if layer == "rule_detection":
            return [
                facts,
                ["matches a known attack pattern"],
                [],
                ["corroborate with additional independent sources before acting"],
            ]
        if layer == "network_behavior":
            return [
                facts,
                ["consistent with possible command-and-control or pivot behavior — attribution unconfirmed"],
                ["no verified TI record confirms the destination"],
                ["collect packet/flow context; verify the destination against TI"],
            ]
        if layer == "anomaly_detection":
            return [
                facts,
                ["behavior deviates from the learned baseline"],
                ["baseline coverage and sample size are not asserted here"],
                ["compare against the host's normal operating window"],
            ]
        if layer == "threat_intelligence":
            return [
                facts,
                ["the observed indicator is linked to verified malicious intelligence"],
                [],
                ["correlate the campaign context and escalate for human approval"],
            ]
        if layer == "correlation":
            return [
                facts,
                ["multiple events may belong to a single activity — not yet established"],
                ["correlation does not prove a common actor"],
                ["review the correlated timeline"],
            ]
        return [facts, [], [], []]

    def _build_facts_and_evidence(
        self, event: SecurityEvent, signals: List[Dict[str, Any]], ti: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        facts: List[str] = []
        evidence: List[str] = []

        entity = (event.entity and event.entity.primary()) or "system"
        facts.append(f"'{event.event_type}' observed for {entity} at {event.timestamp}")
        evidence.append(f"event record {event.event_id} (source: {event.source_system or event.source_agent})")

        for signal in signals:
            for item in signal.get("facts") or []:
                facts.append(item)
            for item in signal.get("evidence") or []:
                evidence.append(f"{signal['layer']}: {item}")

        ti_status = str(ti["status"]).replace("_", " ").upper()
        evidence.append(
            f"Threat Intelligence check: {ti_status} — {ti['records_reviewed']} record(s) reviewed, "
            f"{len(ti['verified_sources'])} verified source(s)"
        )
        return facts, evidence

    def _build_detection(self, event: SecurityEvent, signals: List[Dict[str, Any]]) -> str:
        data = event.data if isinstance(event.data, dict) else {}
        parts: List[str] = []
        declared = data.get("detection") or data.get("rules_triggered")
        if isinstance(declared, str):
            declared = [declared]
        if isinstance(declared, (list, tuple)) and declared:
            parts.append("detection rule(s): " + ", ".join(str(r) for r in declared))
        layers = [s["layer"] for s in signals if s["layer"] != "declared_severity"]
        if "authentication_behavior" in layers:
            parts.append("behavioral pattern: repeated failed authentication attempts")
        if "anomaly_detection" in layers:
            parts.append("anomaly-detection deviation from baseline")
        if "correlation" in layers:
            parts.append("multi-event correlation in the 15-minute window")
        if "network_behavior" in layers:
            parts.append("network-behavior indicators (ports/outbound)")
        if not parts:
            parts.append("no specific rule fired; analysis limited to declared severity only")
        return "; ".join(parts)

    def _build_assessment(
        self, event: SecurityEvent, signals: List[Dict[str, Any]],
        ti: Dict[str, Any], conflicting: bool, insufficient: bool, risk: int,
    ) -> str:
        text = _flatten(event.data if isinstance(event.data, dict) else {}).lower()
        data = event.data if isinstance(event.data, dict) else {}
        failed = self._failed_login_count(data, text)
        ip = (event.entity and event.entity.ip) or None
        sentences: List[str] = []

        if insufficient:
            sentences.append(INSUFFICIENT_EVIDENCE_PHRASE)
            sentences.append("The available evidence does not support a stronger conclusion.")
            return " ".join(sentences)

        brute_force = failed >= 5 and ("ssh" in text)
        repeated_auth = failed >= 5
        if brute_force:
            sentences.append(
                "The IP generated suspicious SSH activity consistent with possible "
                "brute-force behavior."
            )
        elif repeated_auth:
            sentences.append(
                "Repeated failed authentication attempts are consistent with possible "
                "brute-force behavior."
            )
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        outbound = network.get("outbound") if isinstance(network.get("outbound"), dict) else {}
        if outbound.get("ip"):
            sentences.append(
                f"An outbound connection to {outbound.get('ip')}"
                + (f":{outbound.get('port')}" if outbound.get("port") else "")
                + " was observed; the pattern is consistent with possible command-and-control "
                "activity, but attribution is unconfirmed."
            )
        rule_layers = [s for s in signals if s["layer"] == "rule_detection"]
        if rule_layers and not brute_force and not repeated_auth:
            sentences.append(
                "Detection-rule indicators match a known attack pattern; interpretation is "
                "limited to the evidence listed above."
            )
        if not sentences:
            sentences.append(
                "Observed signals deviate from normal operation; the interpretation is "
                "limited strictly to the evidence listed above."
            )

        ti_status = ti["status"]
        if ti_status == ThreatIntelStatus.CONFIRMED:
            sources = ", ".join(ti.get("verified_sources") or []) or "stored TI database"
            indicators = ", ".join(r.get("indicator", "?") for r in ti.get("confirmed_records", [])) or "the observed indicator"
            sentences.append(
                f"The observed indicator(s) ({indicators}) are linked to a verified malicious "
                f"threat-intelligence record (source(s): {sources})."
            )
        elif ti_status == ThreatIntelStatus.NOT_CONFIRMED:
            if brute_force and ip:
                sentences.append(BRUTE_FORCE_UNCONFIRMED_SENTENCE)
            else:
                sentences.append(
                    "No verified evidence currently links the observed indicators to a known "
                    "campaign; no malicious reputation is assigned."
                )
        else:  # UNKNOWN
            sentences.append(
                "Threat intelligence was unavailable at analysis time, so the indicator's "
                "reputation cannot be verified; absence of evidence is not treated as clean."
            )

        if conflicting:
            sentences.append(CONFLICT_PHRASE)
            sentences.append(SUSPICIOUS_NOT_CONCLUSIVE_PHRASE)
            sentences.append(ATTRIBUTION_UNVERIFIED_PHRASE)

        if event.provenance.mode != EventMode.REAL:
            sentences.append(
                f"Data mode: {event.provenance.mode.value.upper()} — not live telemetry."
            )
        return " ".join(sentences)

    def _unknown_information(
        self, event: SecurityEvent, signals: List[Dict[str, Any]],
        ti: Dict[str, Any], conflicting: bool,
    ) -> List[str]:
        unknowns: List[str] = []
        layers = {s["layer"] for s in signals}
        if ti["status"] == ThreatIntelStatus.NOT_CONFIRMED:
            primary = (event.entity and event.entity.primary()) or "the observed indicator"
            unknowns.append(f"No verified threat-intelligence record for {primary}")
        elif ti["status"] == ThreatIntelStatus.UNKNOWN:
            unknowns.append("Threat-intelligence state cannot be verified (service unavailable or not checked)")
        if "anomaly_detection" not in layers:
            unknowns.append("No anomaly/behavioral-baseline data was available")
        if "correlation" not in layers:
            unknowns.append("No correlated events were found in the correlation window")
        if "historical_activity" not in layers:
            unknowns.append("No historical activity for this entity is on record")
        if "authentication_behavior" not in layers:
            unknowns.append("No authentication telemetry was available")
        data = event.data if isinstance(event.data, dict) else {}
        if not (data.get("processes") or data.get("files") or data.get("endpoint")):
            unknowns.append("No endpoint telemetry (process/file) was available")
        if not (data.get("user_behavior") or data.get("behavior")):
            unknowns.append("No user-behavior history was available")
        if conflicting:
            unknowns.append("The conflicting evidence has not been resolved; further investigation required")
        return unknowns or ["None identified from available sources."]

    # ------------------------------------------------------------------
    # Recommendation + human approval (rules 10 and 11) — never execution
    # ------------------------------------------------------------------
    def _source_candidates(self, event: SecurityEvent) -> List[str]:
        data = event.data if isinstance(event.data, dict) else {}
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        candidates: List[str] = []
        for source in network.get("source_ips") or []:
            source = str(source)
            if source and source not in candidates:
                candidates.append(source)
        outbound = network.get("outbound") if isinstance(network.get("outbound"), dict) else {}
        if outbound.get("ip") and str(outbound["ip"]) not in candidates:
            candidates.append(str(outbound["ip"]))
        if not candidates and event.entity and event.entity.ip:
            candidates.append(event.entity.ip)
        return candidates

    def _recommend(
        self, event: SecurityEvent, risk: int, confidence: int,
        ti: Dict[str, Any], insufficient: bool, signals: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        entity = (event.entity and event.entity.primary()) or "system"
        candidates = self._source_candidates(event)
        target = candidates[0] if candidates else entity

        if insufficient:
            return {
                "action": "collect_more_evidence",
                "target": target,
                "impact": "low",
                "requires_human_approval": False,
                "reason": (
                    "Insufficient evidence — further investigation required. Collect "
                    "authentication logs, endpoint telemetry, and threat intelligence "
                    "before any defensive action."
                ),
            }
        if risk >= 70 or ti["status"] == ThreatIntelStatus.CONFIRMED:
            families = self._independent_families(signals)
            independent = len({f for f in families if f in {"rule_detection", "authentication_behavior",
                                                            "network_behavior", "anomaly_detection",
                                                            "correlation", "threat_intelligence",
                                                            "historical_activity"}})
            evidence_phrase = ("with corroborating multi-source evidence"
                               if independent >= 2 else "based on the observed behavior")
            return {
                "action": "block_ip" if candidates else "investigate_source",
                "target": target,
                "impact": "high" if candidates else "low",
                "requires_human_approval": True,
                "reason": (
                    f"Risk {risk}/100 {evidence_phrase}"
                    + (" and verified malicious threat intelligence"
                       if ti["status"] == ThreatIntelStatus.CONFIRMED else "")
                    + (f" on activity sourced from {target}. Blocking is high-impact and "
                       "must be human-approved before execution."
                       if candidates else ". Collect forensic context first.")
                ),
            }
        if risk >= 40:
            return {
                "action": "investigate_host" if (event.entity and event.entity.host) else "correlated_review",
                "target": (event.entity and event.entity.host) or target,
                "impact": "low",
                "requires_human_approval": False,
                "reason": (
                    f"Risk {risk}/100 — review processes, listeners, and authentication "
                    "events; correlate with additional sources before any containment."
                ),
            }
        return {
            "action": "continue_monitoring",
            "target": target,
            "impact": "none",
            "requires_human_approval": False,
            "reason": "Signals are below the action threshold; keep monitoring and log the event.",
        }

    @staticmethod
    def _recommendation_text(rec: Dict[str, Any]) -> str:
        return (
            f"{rec['action']} (target: {rec['target']}; impact: {rec['impact']}) — "
            f"{rec['reason']}"
        )

    def _human_approval_decision(
        self, rec: Dict[str, Any], risk: int, confidence: int, severity: str
    ) -> Tuple[bool, str]:
        if rec["action"] in HIGH_IMPACT_ACTIONS or rec["impact"] == "high":
            return True, (
                "High-impact action — per the anti-hallucination contract, execution requires "
                "policy validation and explicit human approval; the AI only recommends."
            )
        if risk >= 70:
            return True, f"Risk {risk}/100 (severity {severity.upper()}) — {HUMAN_VERIFICATION_PHRASE.lower()} before any containment."
        if confidence < 50 and risk >= 40:
            return True, (
                f"Confidence {confidence}/100 is low with at least medium risk — "
                f"{HUMAN_VERIFICATION_PHRASE}."
            )
        return False, (
            "Only low-impact investigative steps are recommended; no system change is proposed "
            "and no high-impact action is affected."
        )

    # ------------------------------------------------------------------
    # Audit persistence (rule 13)
    # ------------------------------------------------------------------
    def _persist_audit(
        self, event: SecurityEvent, analysis: SecurityAnalysis,
        ti: Dict[str, Any], rec: Dict[str, Any],
    ) -> None:
        data = event.data if isinstance(event.data, dict) else {}
        tools_used: List[str] = ["SecurityEvent payload (event bus)"]
        if data.get("authentication"):
            tools_used.append("SIEM/authentication telemetry (event.data.authentication)")
        if isinstance(data.get("network"), dict):
            tools_used.append("network telemetry (event.data.network)")
        if isinstance(event.threat_intelligence, dict) and event.threat_intelligence:
            tools_used.append("Threat Intelligence (Vrin_TI gateway / local TI database)")
        if isinstance((event.analysis or {}).get("anomaly"), dict):
            tools_used.append("Data Science anomaly engine (event.analysis.anomaly)")
        if event.correlation:
            tools_used.append("SOC correlation engine (event.correlation)")

        declared = data.get("detection") or data.get("rules_triggered")
        if isinstance(declared, str):
            declared = [declared]
        rules_triggered: List[str] = []
        if isinstance(declared, (list, tuple)):
            rules_triggered.extend(str(r) for r in declared)
        if any(s["layer"] == "authentication_behavior" and s["score"] >= 60 for s in analysis.signals):
            rules_triggered.append("failed_auth_threshold (inferred)")
        if any(s["layer"] == "anomaly_detection" for s in analysis.signals):
            rules_triggered.append("anomaly_deviation (inferred)")

        raw_evidence = {
            "input_event_id": event.event_id,
            "entity": event.entity.model_dump() if event.entity else {},
            "data": event.data,
            "threat_intelligence": event.threat_intelligence,
            "analysis": event.analysis,
            "risk": event.risk,
            "correlation": event.correlation,
            "provenance": event.provenance.model_dump(),
            "facts": analysis.facts,
            "findings": [f.model_dump() for f in analysis.findings],
        }

        report = render_report(analysis)

        db = _db()

        def upsert(conn):
            conn.execute(
                """
                INSERT INTO evidence_audit (
                    analysis_id, event_id, correlation_id, timestamp, raw_evidence, tools_used,
                    ti_sources, rules_triggered, correlation_results, ai_assessment,
                    risk_score, confidence, severity, threat_intelligence, recommended_action,
                    human_decision, final_action, report, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    human_decision = excluded.human_decision,
                    final_action = excluded.final_action
                """,
                (
                    analysis.analysis_id,
                    analysis.event_id,
                    analysis.correlation_id,
                    analysis.created_at,
                    json.dumps(raw_evidence, default=str),
                    json.dumps(tools_used),
                    json.dumps(ti.get("verified_sources") or []),
                    json.dumps(rules_triggered),
                    json.dumps(event.correlation if isinstance(event.correlation, dict) else {}),
                    analysis.assessment,
                    analysis.risk_score,
                    analysis.confidence,
                    analysis.severity,
                    analysis.threat_intelligence.value,
                    analysis.recommended_action,
                    None,
                    None,
                    report,
                    analysis.created_at,
                ),
            )

        try:
            db._run_db(upsert)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(f"audit persist failed: {exc}")

    @staticmethod
    def _row_to_record(row) -> Dict[str, Any]:
        record = {
            "analysis_id": row[0],
            "event_id": row[1],
            "correlation_id": row[2],
            "timestamp": row[3],
            "raw_evidence": json.loads(row[4] or "{}"),
            "tools_used": json.loads(row[5] or "[]"),
            "ti_sources": json.loads(row[6] or "[]"),
            "rules_triggered": json.loads(row[7] or "[]"),
            "correlation_results": json.loads(row[8] or "{}"),
            "ai_assessment": row[9],
            "risk_score": row[10],
            "confidence": row[11],
            "severity": row[12],
            "threat_intelligence": row[13],
            "recommended_action": row[14],
            "human_decision": row[15],
            "final_action": row[16],
            "report": row[17],
            "created_at": row[18],
        }
        return record

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    def _model_info(self) -> Dict[str, Any]:
        return {
            "engine": ENGINE_VERSION,
            "deterministic": True,
            "llm": False,
            "contract": "VRINDHA_AI_PROMPT (13 rules, anti-hallucination)",
            "high_impact_actions_never_executed": sorted(HIGH_IMPACT_ACTIONS),
        }


def _safe_float(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    if result != result or result in (float("inf"), float("-inf")):  # NaN / inf guard
        return 0.0
    return result


vrindha_ai = VrindhaAI()

__all__ = [
    "VRINDHA_AI_PROMPT",
    "VrindhaAI",
    "vrindha_ai",
    "render_report",
    "enforce_claim_guard",
    "INSUFFICIENT_EVIDENCE_PHRASE",
    "CONFLICT_PHRASE",
    "SUSPICIOUS_NOT_CONCLUSIVE_PHRASE",
    "ATTRIBUTION_UNVERIFIED_PHRASE",
    "HUMAN_VERIFICATION_PHRASE",
    "HIGH_IMPACT_ACTIONS",
    "ENGINE_VERSION",
]
