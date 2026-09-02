# Vrindha AI — Anti-Hallucination & Evidence-Grounded Security Analysis

The operating contract of **Vrindha AI**, the evidence-grounded security
analysis agent of the HIVE coordination layer. The full contract text is the
constant `VRINDHA_AI_PROMPT` in
[`vrin_SOC/coordination/evidence_analysis.py`](../vrin_SOC/coordination/evidence_analysis.py)
and is served verbatim by `GET /analysis/prompt` — the agent's rules are
themselves auditable.

> **Final operating principle:**
> *"Evidence before inference. Inference before action.
> Verification before high-impact action."*

The engine is **deterministic** (no free-text LLM output): every number and
every claim is derived from the event's stored evidence sections, so results
are reproducible, explainable, and traceable. A claim guard additionally
strips any unsupported attribution claim (e.g. "part of a ransomware
campaign") from the assessment unless a verified threat-intelligence record
supports it.

## The 13 rules and where they are implemented

| # | Rule | Implementation |
|---|------|----------------|
| 1 | Never invent, assume, or fabricate evidence; distinguish FACT / INFERENCE / UNKNOWN; say exactly *"Insufficient evidence — further investigation required."* when evidence is thin | `VrindhaAI._analyze` classifies every finding; `INSUFFICIENT_EVIDENCE_PHRASE` is emitted verbatim when fewer than two meaningful independent signals exist and TI is not confirmed |
| 2 | Evidence-first order (tool data → raw evidence → validation → TI → rules/correlation → reasoning → risk+confidence → human verification → controlled response) | `_analyze` pipeline stages in that order; execution never happens inside the analyzer |
| 3 | Never make unsupported claims (canonical example: 37 failed SSH attempts, no TI ⇒ no ransomware-campaign claim) | `enforce_claim_guard` removes forbidden attribution terms without TI; the canonical sentence *"No verified evidence currently links the IP to a ransomware campaign."* is emitted for the unconfirmed brute-force case |
| 4 | Verify threat intelligence: retrieve, verify source, check freshness, compare IOC with the observed event; no supporting intelligence ⇒ **NOT CONFIRMED**; never create a reputation | `_verify_threat_intelligence`: unsourced records are unusable, stale records (batch > 24 h vs. event; record `last_seen` > 180 days) are not confirmed, non-matching IOCs are not confirmed; TI absence is never treated as "clean" |
| 5 | Separate FACT from INTERPRETATION for every finding (FACT / EVIDENCE / INFERENCE / UNKNOWN / RECOMMENDATION) | `ClassifiedFinding` model — one field per class of statement; inferences are always hedged ("consistent with possible …") |
| 6 | Multi-source correlation (SIEM, network, auth, endpoint, TI, firewall, IDS, hashes, user behavior, history, rules) | Independent signal layers in `_extract_signals`; only **independent** families count as corroboration (rule + auth layers driven by the same failed-logins observation count once; a declared severity is never corroboration) |
| 7 | Risk 0–100, Confidence 0–100, Severity LOW/MEDIUM/HIGH/CRITICAL; never "feel" confidence | `_compute_risk` / `_compute_confidence` — weighted, capped, documented; confidence is bounded at 97 (Vrindha never claims certainty) |
| 8 | Uncertainty handling: conflict ⇒ no forced conclusion, explain it, lower confidence, request investigation | `_detect_conflicts` (benign TI vs. strong local signal, explicit conflict flag, unsupported CRITICAL severity); conflict ⇒ risk capped at 65, confidence halved (≤ 40), exact contract phrases emitted |
| 9 | Structured `[SECURITY ANALYSIS]` output | `render_report` — Event, FACTS, EVIDENCE, DETECTION, ASSESSMENT, RISK SCORE, CONFIDENCE, THREAT INTELLIGENCE, UNKNOWN INFORMATION, RECOMMENDED ACTION, HUMAN APPROVAL, REASON |
| 10 | High-impact action protection: block IP, disable account, isolate machine, firewall changes, file deletion, kill process, config changes ⇒ AI Recommendation → Policy Validation → Human Approval → Controlled Execution | `HIGH_IMPACT_ACTIONS` is recommend-only; execution happens only through the existing Commander → Ethics → human-approval → automation chain |
| 11 | Human-in-the-loop: low confidence or high impact ⇒ DO NOT EXECUTE, "Human verification required." | `_human_approval_decision` — required for high-impact recommendations, risk ≥ 70, or confidence < 50 with at least medium risk |
| 12 | Feedback loop: analyst decision ⇒ feedback database ⇒ rule/detection improvement; never silently change historical evidence or audit records | `record_feedback` — append-only `analysis_feedback` table; the only mutable audit fields are the contract's own "Human Decision" and "Final Action" columns |
| 13 | Auditability: preserve alert ID, timestamp, raw evidence, tools used, TI sources, rules triggered, correlation results, AI assessment, risk, confidence, recommended action, human decision, final action | `evidence_audit` SQLite table, one row per analysis, retrievable via `GET /analysis/{analysis_id}` |

## Threat-intelligence states

`ThreatIntelStatus` has exactly three values, matching the contract:

| State | Meaning |
|---|---|
| `CONFIRMED` | A retrieved TI record **matches the observed indicator**, has at least one **verified source**, and is **fresh** |
| `NOT CONFIRMED` | No supporting intelligence exists — checked and empty, record stale, record unsourced, or IOC mismatch. **No reputation is invented** |
| `UNKNOWN` | TI could not be checked at this time (service unavailable/degraded) — the state cannot be verified; **absence is not treated as clean** |

## Usage

### CLI / Python

```python
from vrin_SOC.coordination.evidence_analysis import vrindha_ai, render_report
from vrin_SOC.coordination.schemas import SecurityEvent

event = SecurityEvent(
    event_type="auth_failure",
    entity={"ip": "192.168.1.50"},
    data={"authentication": {"failed_login_count": 37, "service": "ssh"}},
    severity="high",
)
analysis = vrindha_ai.analyze(event)
print(render_report(analysis))
```

### REST API (JWT required)

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /analysis/prompt` | user | The verbatim 13-rule operating contract |
| `POST /analysis/security` | user | Evidence-grounded analysis for one event payload (full `SecurityEvent` shape or flat) → `SecurityAnalysis` + rendered `[SECURITY ANALYSIS]` report |
| `GET /analysis/{analysis_id}` | user | Full preserved audit record (rule 13) |
| `GET /analysis/audit?limit=50` | user | Recent analysis audit records, newest first |
| `POST /analysis/{analysis_id}/feedback` | user | Record an analyst decision — `{analyst, decision, notes}` with `decision ∈ {true_positive, false_positive, insufficient_evidence, unknown}` (rule 12) |
| `GET /analysis/feedback?limit=50` | user | The analyst feedback database, newest first |

Example:

```bash
curl -s localhost:8000/analysis/security \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"event_type":"auth_failure","entity":{"ip":"192.168.1.50"},
       "data":{"authentication":{"failed_login_count":37,"service":"ssh"}},
       "severity":"high"}'
```

## Worked example (the contract's own rule-3 example)

Input: IP `192.168.1.50`, 37 failed SSH attempts, no verified malicious TI record.

```text
[SECURITY ANALYSIS]

Event:
auth_failure on 192.168.1.50 at … (source: external)

FACTS:
- 'auth_failure' observed for 192.168.1.50 at …
- failed-authentication threshold exceeded (37)
- 37 failed authentication attempt(s) recorded over SSH
- source system declared severity high

EVIDENCE:
- event record evt-… (source: external)
- rule_detection: authentication telemetry (event.data.authentication)
- authentication_behavior: authentication telemetry (event.data.authentication)
- Threat Intelligence check: NOT CONFIRMED — 0 record(s) reviewed, 0 verified source(s)

DETECTION:
behavioral pattern: repeated failed authentication attempts

ASSESSMENT:
The IP generated suspicious SSH activity consistent with possible brute-force
behavior. No verified evidence currently links the IP to a ransomware campaign.

RISK SCORE:
83

CONFIDENCE:
74

THREAT INTELLIGENCE:
NOT CONFIRMED

UNKNOWN INFORMATION:
- No verified threat-intelligence record for 192.168.1.50
- …

RECOMMENDED ACTION:
block_ip (target: 192.168.1.50; impact: high) — … must be human-approved
before execution.

HUMAN APPROVAL:
REQUIRED

REASON:
High-impact action — per the anti-hallucination contract, execution requires
policy validation and explicit human approval; the AI only recommends.
```

The system never says *"192.168.1.50 is part of a ransomware campaign."* —
that claim is both absent from the report and actively stripped by the claim
guard if it ever appears upstream.

## Data ownership

| Store | Written by |
|---|---|
| `evidence_audit` (one row per analysis) | Vrindha AI only; `human_decision` / `final_action` are updated by the feedback step (the contract's Human Decision / Final Action) |
| `analysis_feedback` (append-only) | Vrindha AI via `record_feedback` |

No other agent writes these stores; raw inputs are snapshotted into
`raw_evidence` so every conclusion stays reconstructable.

## Tests

`vrin_SOC/tests/test_evidence_analysis.py` (34 tests) covers the contract:
the verbatim prompt, the rule-3 canonical example (forbidden claim absent,
recommended wording present, `NOT CONFIRMED`), the exact insufficient-evidence
phrase, the report format and section order, FACT/INFERENCE separation, TI
CONFIRMED/NOT CONFIRMED/UNKNOWN (sourced+fresh vs. unsourced vs. stale vs.
unavailable), conflict handling (confidence lowered, conclusion capped),
multi-source corroboration raising confidence, human-approval gating,
claim-guard unit behavior, the 13-field audit record, the append-only feedback
loop, pipeline integration, data-mode honesty (SIMULATED labeling), and the
REST endpoints (auth, roundtrip, 404, feedback validation).
