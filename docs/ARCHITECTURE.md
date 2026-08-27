# HIVE Intelligence — Coordination Architecture

This document describes the coordinated multi-agent layer added to Vrindha SOC
(`vrin_SOC/coordination/`). It builds on — and does not replace — the existing
Core Brain, Red/Blue Team modules, SIEM, and the independent `Vrin_TI` service.

## 1. Design goals

1. **Orchestration without coupling.** Agents communicate only through a shared
   event bus. No agent imports another agent's internals to drive it.
2. **Defensive, human-controlled authority.** Data Science and SOC agents can
   *recommend*; only an authenticated human (admin) can approve a high-impact
   action (block IP, isolate host, firewall change, …).
3. **No fabrication.** Threat intelligence, model results, evidence, telemetry,
   and Gita verses are either verified from a real source or explicitly labeled
   `SIMULATED` / `MOCK` / `FALLBACK`. Missing data is reported as unavailable —
   never invented.
4. **Explainability.** Every anomaly score and risk score ships with factor
   contributions and a human-readable explanation.
5. **Graceful degradation.** A failing agent is recorded in a dead-letter queue
   and marked `degraded`; the pipeline continues and never pretends success.

## 2. Agents

| Agent | Module | Responsibility | Authority |
|---|---|---|---|
| Commander AI | `coordination/commander.py` | Incident lifecycle, correlation, approval gate, orchestration | Orchestrates; executes nothing destructive by itself |
| Infrastructure AI | `coordination/infrastructure_ai.py` | Collect local telemetry (CPU/mem/disk/net/processes) | Observe-only |
| Threat Intelligence AI | `coordination/threat_intel_ai.py` | IOC extraction + enrichment via `Vrin_TI` | Lookup only; degrades to `unavailable`, never fabricates reputation |
| Data Science AI | `coordination/data_science_ai.py` | Ingest → validate → clean → integrate → EDA → features → anomaly → risk → evaluate → explain → feedback | Analysis only; never executes high-impact actions |
| SOC Analyst AI | `coordination/soc_analyst_ai.py` | Triage, 15-minute correlation, investigation summary, recommendations | Recommends; humans approve |
| Knowledge AI | `coordination/knowledge_ai.py` | Stores **validated** lessons; search; validated-sample feed for DS | Read/store validated outcomes only |
| Ethics & Compliance AI | `coordination/ethics_ai.py` | Action-level Dharma classification, decision matrix, verified Gita guidance, teach mode, ethics audit log | Governs; judges the *action*, never the user |

Every agent inherits `BaseAgent` (`coordination/observability.py`) which
provides: identity (`name`, `agent_version`, `capabilities`), a call metric
window (counts, errors, p50/p95 latency), an error streak → `degraded` health,
and `run_guarded()` which converts exceptions into
`{"status": "error", "degraded": true, ...}` instead of crashing the pipeline.

Agents self-register with the existing Hive coordinator
(`vrin_SOC/hive/coordinator.py`) so they appear in HIVE health views.

## 3. Event flow

```text
raw event (real telemetry OR labeled SIMULATION payload)
   │
   ▼
Data Science AI.ingest ── schema + quality checks ──► recorded rejection (never silent)
   │
   ▼
SecurityEvent (validated, pydantic) ──► Commander.handle_event
   │
   ├─► Incident created or reused (find_open_by_correlation)
   ├─► Threat Intelligence AI.enrich  (TI lookup; unavailable ⇒ marked)
   ├─► Data Science AI.analyze        (features → anomaly → risk, explained)
   ├─► publish on event bus           (every subscriber sees the same event)
   ├─► SOC Analyst AI.investigate     (correlation window, evidence, recommendations)
   └─► Ethics & Compliance AI.evaluate (action-level decision)
           │
           ├─► high-impact proposal + ethics passed  ⇒  status: awaiting_approval
           ├─► explicit correlation, no high impact  ⇒  status: open_monitoring
           └─► no correlation                        ⇒  status: closed_monitoring
           │
           ▼
   HUMAN APPROVAL (admin, POST /commander/approve)  or  REJECTION
           │
           ├─► approve ⇒ authorized_response (e.g. simulated block_ip)
           │           ⇒ Knowledge AI stores validated lesson
           │           ⇒ Data Science receives validated label (feedback loop)
           │           ⇒ incident CLOSED, trace complete
           └─► reject  ⇒ incident REJECTED, no action taken
```

**Correlation.** Events sharing a `correlation_id` within 15 minutes fold into
one incident and one aggregate risk (`max` of member event risks). The SOC
analyst exposes `aggregate_risk` in its investigation; the block threshold is
`aggregate_risk ≥ 0.5` **or** a malicious IOC, and only for an identifiable
*source* address (victim addresses are never blocked).

## 4. Event bus

`coordination/event_bus.py` — in-process pub/sub with:

- `emit()` / `publish()` — strong typing via `SecurityEvent`; every event gets
  an id, timestamp, status, provenance, and optional correlation id.
- `subscribe(event_type, handler, subscriber)` — exact type or `*` wildcard;
  handlers may return annotations that are merged back into the event
  (`threat_intelligence`, `analysis`, `risk`, `correlation`).
- `correlate(correlation_id)` — retrieve the event family.
- `acknowledge()` / `update()` — status lifecycle on stored events.
- Dead-letter queue — a raising handler is recorded (subscriber, event id,
  error) and does not stop delivery to other subscribers.
- Pluggable `InMemoryTransport` with `peek()` for observability.

The bus stores a bounded in-process history used by dashboards and model
evaluation; it is not a persistence layer (incidents, knowledge, and audit
rows live in SQLite via `vrin_SOC/database/db.py`).

## 5. Data storage separation

| Store | Contents |
|---|---|
| Raw inputs | `DataQualityReport.rejected_records` (in-process, bounded) + SQLite `coordination_*` tables for accepted incidents |
| Processed | `SecurityEvent` records (typed, validated) |
| Features | rolling time-window store (1m/5m/15m/1h/24h), in-process, per host |
| Model outputs | `event.analysis` (anomaly), `event.risk` (risk) attached to events |
| Incidents | SQLite `coordination_incidents` (status, trace JSON, approvals, knowledge link) |
| Model metadata | in-process versioned registry (see `docs/MODEL_CARD.md`) |
| Knowledge | SQLite `knowledge_lessons` + `incident_outcomes` (validated lessons only) |
| Ethics audit | SQLite `ethics_audit_log` (every decision) |

## 6. Real vs simulated

`SecurityEvent.provenance.mode ∈ {real, simulated, mock, fallback}` is set at
the source and surfaced in every API/dashboard response that includes events:

- Real host telemetry → `real` (or `fallback` with explicit unavailable
  sections when the platform lacks the counters — the fallback is marked, not
  silently zero-filled).
- The demonstration scenario → every payload carries `SIMULATION: true` and
  `provenance.mode = simulated`; the API response repeats the simulation note.
- Threat intelligence without a reachable TI source → `unavailable`
  determination, `malicious = None` (absence of evidence, not clean evidence).

## 7. Boundaries with existing systems

- The **Core Brain** (intent → authorization → Dharma → safety) still guards
  CLI/API commands. The coordination layer's Ethics & Compliance AI governs
  *incident-driven defensive actions* and reuses the same Dharma principle set
  and verified Gita dataset — it does not re-score users and does not bypass
  Brain safety.
- **`Vrin_TI`** remains an independent service; Threat Intelligence AI calls it
  over its public API and degrades gracefully when it is down.
- **Automation actions** (e.g. `automation/actions.py::block_ip`) are the only
  execution path for defensive responses; they validate inputs and run in
  simulation mode in this deployment (no real firewall mutation without a
  human-approved, operator-configured mode).

## 8. Failure semantics

| Failure | Behavior |
|---|---|
| Handler raises on the bus | Dead-letter entry; other subscribers unaffected |
| Agent dependency missing | `run_guarded` returns `degraded` result; pipeline marks the contribution unavailable |
| TI unreachable | `malicious: None`, explainability notes the degradation |
| Insufficient labels for evaluation | `insufficient_data` — metrics are never fabricated |
| Invalid raw event | Recorded rejection with reason; counted in data quality |
