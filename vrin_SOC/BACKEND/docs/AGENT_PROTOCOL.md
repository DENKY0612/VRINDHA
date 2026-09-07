# Agent Protocol — HIVE Coordination Layer

Contract for the coordination agents: the shared event schema, bus semantics,
observability, and failure behavior. All agents live in
`vrin_SOC/coordination/` and register with the existing HIVE coordinator
(`vrin_SOC/hive/coordinator.py`).

## 1. Agent identity

Every agent subclasses `BaseAgent` (`coordination/observability.py`):

```python
name: str                 # e.g. "DataScienceAI"
agent_version: str        # e.g. "1.0"
capabilities: [str]       # machine-readable capability list
```

On construction the agent registers with the HIVE coordinator and emits a
heartbeat, so HIVE health views include coordination agents automatically.

### Observability contract (per agent)

`health()` returns at minimum:

```jsonc
{
  "agent": "DataScienceAI",
  "version": "1.0",
  "status": "healthy | degraded",   // error streak ≥ 5 ⇒ degraded
  "calls": 123, "errors": 0, "error_rate": 0.0,
  "latency_ms": {"avg": 1.2, "p50": 1.0, "p95": 3.4},
  "capabilities": ["data_ingestion", "..."],
  "model": { ... }                  // agent-specific model metadata
}
```

`run_guarded(fn)` wraps any pipeline step: on exception it records the error
and returns `{"status": "error", "degraded": true, "error": ..., "note": ...}`
— **the pipeline continues; no agent crash is fatal to the SOC.**

## 2. The shared event schema

`coordination/schemas.py` (Pydantic v2). One strongly-typed event shape is
used by every agent — no agent invents its own wire format.

### SecurityEvent (top level)

| Field | Type | Notes |
|---|---|---|
| `event_id` | str | `evt-<uuid12>`, assigned on creation |
| `event_type` | str | non-empty (e.g. `security_event`, `telemetry`) |
| `timestamp` | ISO-8601 | UTC; validated by ingest (≤ +5 min skew) |
| `severity` | low\|medium\|high\|critical | normalized lowercase |
| `source_agent` | str | agent that created/owns the event |
| `status` | enum | `new → ingested → risk_assessed → correlated → approved / closed / rejected` |
| `correlation_id` | str? | families events into one incident |
| `entity` | EntityRef | `ip`, `host`, `domain`, `user`, `process`, `device`, `ports`… |
| `data` | dict | raw payload (auth, network, process, resource sections) |
| `provenance` | Provenance | **required honesty field** — see below |
| `threat_intelligence` | dict? | TI annotations (merged by bus handlers) |
| `analysis` | dict? | DS annotations (`anomaly`, `features`, …) |
| `risk` | dict? | risk engine output (`risk_score`, `factors`, `explainability`) |
| `correlation` | dict? | SOC correlation results |
| `trace` | list | per-stage audit entries |

### Provenance (anti-fabrication)

```jsonc
{ "mode": "real | simulated | mock | fallback", "source": "...", "generated_at": "..." }
```

- `real` — measured on the live host.
- `simulated` — synthetic (the demo scenario is 100% simulated and every
  payload carries `SIMULATION: true`).
- `mock` — canned test data.
- `fallback` — a real source was unavailable; unavailable sections are
  explicit `{"status": "unavailable", ...}` entries, never zero-filled as if
  measured.

`mode` is an enum — free-text "probably real" is rejected at validation time.

### EthicsAssessment (action-level, never user-level)

`requested_action`, `classification`
(`dharma_aligned | ethically_neutral | ethical_concern | potential_adharma |
high_risk_adharma | illegal_or_unauthorized`), `decision`
(`allow | allow_with_warning | require_authorization | safe_alternative |
deny | escalate_to_human`), authorization status, harm/deception/privacy risk,
principles, policy/legal references, verified Gita reference (optional),
`human_approval_required`. **No field scores or labels the user** — the model
deliberately has no moral-score column.

### Incident

`incident_id`, `title`, `correlation_id`, `status`
(`open | investigating | awaiting_approval | approved | responded | closed |
rejected`), `event_ids`, `proposed_action`, `ethics` (assessment snapshot),
`response_result`, `approved_by`, `knowledge_id`, `trace[]` (full stage audit).

### SecurityAnalysis (anti-hallucination output)

Vrindha AI's structured result: `analysis_id`, `event_id`, `facts[]`,
`evidence[]`, `findings[]` (`ClassifiedFinding`: fact / evidence / inference /
unknown / recommendation — one field per class of statement), `detection`,
`assessment`, `risk_score` (0–100), `confidence` (0–100), `severity`
(`low | medium | high | critical`), `threat_intelligence`
(`confirmed | not_confirmed | unknown`), `ti_detail`, `unknown_information[]`,
`recommended_action`, `action_impact`, `human_approval_required`, `reason`,
`evidence_conflicting`, `insufficient_evidence`, `claim_guard_triggered`,
`signals[]` (explainable layers), `mode`, `created_at`.

## 3. Event bus contract

`EventBus` (in-process, pluggable transport):

- `emit(**fields)` — construct + store + return a `SecurityEvent` (no
  delivery).
- `publish(event)` — deliver to subscribers for `event.event_type` and `*`;
  collect handler annotations and merge them back into the event; append to
  bounded history; return a delivery report (`delivered`, `errors[]`).
- `subscribe(event_type, handler, subscriber)` — returns an id; `unsubscribe(id)`.
  Handlers may return a dict to annotate the event (`{"analysis": {...}}`).
- `correlate(correlation_id)` — event family for one correlation.
- `acknowledge(event_id, status, actor)` / `update(event_id, annotations)` —
  lifecycle + late annotations on stored events.
- `dead_letter()` — every handler that raised, with subscriber, event id,
  error, timestamp. A failing agent is **recorded, isolated, and observable**
  — it never blocks other subscribers.
- `stats()` — `published`, `delivered`, `failed`, `subscribers`.

**Rule: no direct agent-to-agent calls for pipeline flow.** The Commander
drives an incident by *calling* each specialist in order (that is
orchestration, allowed), but the result of every specialist is published on
the bus, so any future agent can observe the same artifacts without coupling.

## 4. Incident lifecycle (Commander)

```text
ingest → incident (created or reused via correlation)
       → threat_intelligence → data_science → publish
       → soc_investigation → ethics
       → awaiting_approval   (high-impact proposal passed ethics)
         | open_monitoring   (explicit correlation, no high-impact action)
         | closed_monitoring (uncorrelated single event; knowledge "unknown")
       → [human] approve → authorized_response → knowledge → DS feedback → CLOSED
                 or reject → REJECTED (no action)
```

Each stage appends an `incident.trace` entry (`stage`, agent, payload) so the
whole decision chain is reconstructable from the stored incident row
(SQLite `coordination_incidents`).

Approval is **admin-only** (JWT role check) and records `approved_by`,
conclusion, and justification. The defensive response (e.g. `block_ip`) runs
*after* approval, is validated (real IP syntax), and in this deployment runs
in **simulation** — the result is stored with `status: "simulated"` and the
exact action that *would* run.

## 5. Ethics gate contract

`EthicsAI.evaluate(action, target, context, authorization_status,
request_gita_guidance, event_id)` — multi-layer decision:
intent → authorization → policy → law (guidance, not advice) → dharma → risk
→ Gita (verified only) → decision.

- Every decision is written to `ethics_audit_log` (SQLite) — searchable via
  `GET /ethics/audit`.
- Gita references come **only** from the stored, chapter-verified dataset
  (`vrin_SOC/data/BhagavadGita/`, 18 chapters / 700 verses). A reference that
  is not in the dataset is never emitted. Guidance is optional and can be
  declined by the caller.
- The engine judges the **action + context**. Output text never labels,
  ranks, or profiles the user; teach mode is educational, not judgmental.

## 6. Data ownership

| Agent | Writes |
|---|---|
| Infrastructure AI | telemetry events (bus, labeled real/fallback) |
| Threat Intel AI | `event.threat_intelligence` annotations |
| Data Science AI | `event.analysis`, `event.risk`, feature store, registry, `incident_outcomes` (validated only), data-quality counters |
| SOC Analyst AI | `event.correlation`, investigation dicts (transient; stored in incident trace) |
| Knowledge AI | `knowledge_lessons`, validated samples |
| Ethics AI | `ethics_audit_log` |
| Commander AI | `coordination_incidents` |
| Vrindha AI | `evidence_audit` (one row per analysis; only `human_decision`/`final_action` are mutable), `analysis_feedback` (append-only) |

No two agents write the same store.

## 7. Vrindha AI — anti-hallucination contract

`coordination/evidence_analysis.py` implements the 13-rule
anti-hallucination contract (see [`ANTI_HALLUCINATION.md`](ANTI_HALLUCINATION.md)):
FACT/INFERENCE/UNKNOWN separation, verified TI state
(`CONFIRMED | NOT CONFIRMED | UNKNOWN`), explainable risk 0–100 + confidence
0–100, conflict handling, the structured `[SECURITY ANALYSIS]` report,
recommend-only high-impact actions (execution stays in the Commander →
Ethics → human chain), the append-only analyst feedback loop, and the
per-analysis audit row. Its operating rules are served verbatim at
`GET /analysis/prompt`.
