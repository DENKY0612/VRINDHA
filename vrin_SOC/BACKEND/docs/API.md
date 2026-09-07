# HIVE Coordination API

REST endpoints for the coordination layer, served by the existing FastAPI
application (`vrin_SOC/api/main.py` → `vrin_SOC/api/coordination_routes.py`).
Interactive docs remain at `/docs` (tag **coordination**).

## Authentication

All coordination endpoints require the standard `Authorization: Bearer <JWT>`
header (from `POST /login` or first-admin `POST /register`).
**Admin-only** endpoints are marked ⭐; non-admins receive `403`.

Unauthenticated requests receive `401 {"detail": "Bearer authentication
required"}`.

## Data Science AI

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /data-science/health` | user | Agent health + model metadata |
| `GET /data-science/status` | user | Health + data quality + bus stats + models + validated sample count |
| `GET /data-science/metrics` | user | Evaluation metrics vs validated labels (or explicit `insufficient_data`) |
| `GET /data-science/models` | user | Versioned model registry (status, hyperparameters, provenance) |
| `POST /data-science/events` | user | Ingest one raw event → accepted event or recorded rejection; optional `run_pipeline: true` to run the full Commander pipeline |
| `POST /data-science/analyze` | user | Run the coordinated pipeline for a command/event (`{"command": "..."}`) |
| `POST /data-science/anomaly` | user | Anomaly detection for one event payload (full `SecurityEvent` shape or flat) |
| `POST /data-science/risk` | user | Explainable risk score for one event payload |
| `POST /data-science/features` | user | Feature vector + window counts for one event payload |

## Agent observability

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /agents/health` | user | Health of all 8 coordination agents + bus stats |

## Commander (incidents & approval gate)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /commander/events` | user | Ingest an event into the full pipeline (human-approval gate applies) |
| `GET /commander/incidents?limit=50` | user | Recent incidents (newest first) |
| `GET /commander/incidents/{incident_id}` | user | Full incident: status, trace, proposed action, ethics, response |
| `POST /commander/approve?incident_id=...` ⭐ | admin | **Human approval** of the proposed action; body: `{approver, conclusion, justification, action_override?}`. Runs the controlled (simulated) response through the response engine (allowlist check, rollback record, expiry, no chaining), stores the validated knowledge lesson, feeds DS labels, closes the incident. `action_override` lets the human escalate to another catalog action (e.g. `block_ip`) — a justification is then required |
| `POST /commander/reject?incident_id=...` ⭐ | admin | Reject the proposal; body: `{approver, reason}`. No action is taken; a `contained` incident's temporary containment is rolled back |
| `POST /commander/incidents/{incident_id}/rollback` | admin | Roll back every reversible action recorded on the incident; body: `{operator, reason}` |

Pipeline responses now carry `response_decision`, `action_preview` (the
`ACTION PREVIEW` block) and `vrindha_response` (the `[VRINDHA RESPONSE]`
block). A new status `contained_pending_review` is returned when an explicitly
configured emergency policy applied temporary containment.

## Controlled Autonomous Response (safety contract)

See [`CONTROLLED_AUTONOMY.md`](CONTROLLED_AUTONOMY.md) for the full contract
(three-level autonomy, critical assets, allowlist, reversibility, emergency
policies, rollback, time limits, safe mode, audit).

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /response/prompt` | user | The verbatim 15-section safety contract |
| `GET /response/policy` | user | Allowlist, thresholds, action catalog with autonomy levels, emergency policies, safe-mode state |
| `PUT /response/policy/allowlist` | admin | Human-configured trusted-asset allowlist; body: `{operator, trusted_ips?, trusted_domains?, critical_servers?, security_tools?, administrative_accounts?, essential_processes?, internal_networks?}` |
| `POST /response/policy/emergency` | admin | Register an explicit emergency policy `{operator, policy}`; invalid policies are **rejected** with reasons (LEVEL 3 / irreversible / unbounded policies are never accepted) |
| `GET /response/safe-mode` · `POST /response/safe-mode` | user · admin | Read / enter / exit SAFE MODE `{operator, enabled, reason}` |
| `POST /response/decide` | user | Classify a proposed response **without executing**; body: `{event, action, target}` → decision, `action_preview`, `vrindha_response` |
| `GET /response/audit?limit=50` | user | Response audit — decision columns immutable; execution / rollback / human review appended |
| `GET /response/{decision_id}` | user | One decision with its execution result, rollback info, reviews, preview and response block |
| `GET /response/rollbacks?limit=50&active_only=false` | user | Rollback records (active temporary actions with `active_only=true`) |
| `POST /response/rollbacks/{action_id}/rollback` | admin | Roll back one action `{operator, reason}` |
| `POST /response/rollbacks/{action_id}/extend` | admin | Extend a temporary action after re-evaluation `{operator, minutes, justification}` |
| `POST /response/expire` | admin | Roll back all temporary actions whose time limit has passed |
| `POST /response/{decision_id}/review` · `GET /response/reviews` | user | §14 post-response review (validated reviews only feed learning) |

## Ethics & Compliance (Dharma + verified Gita)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /ethics/evaluate` | user | Action-level decision for `{action, target, context, authorization_status, gita_guidance}` |
| `GET /ethics/audit?limit=50` | user | Ethics decision audit log (newest first) |
| `GET /ethics/gita/chapters` | user | 18-chapter index + verse count + source |
| `GET /ethics/gita/{chapter}/{verse}` | user | One stored verse (`verified: true`). `422` out of range (1–18 / 1–300); `404` when the verse is not in the stored dataset — **a missing verse is never fabricated** |
| `POST /ethics/gita/search` | user | Search the stored dataset only |
| `POST /ethics/teach` | user | Educational explanation of a concern (`{topic, gita_guidance}`) — no judgment of the user |

## Knowledge AI

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /knowledge/lessons?limit=50` | user | Validated lessons (newest first) |
| `POST /knowledge/search` | user | Search lessons by pattern |
| `POST /knowledge/record` ⭐ | admin | Store a **validated** outcome `{incident_id, conclusion, summary, event_ids, pattern, validated_by}` |

## Vrindha AI — anti-hallucination, evidence-grounded analysis

See [`ANTI_HALLUCINATION.md`](ANTI_HALLUCINATION.md) for the full contract
(13 rules, TI states, claim guard, audit/feedback semantics).

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /analysis/prompt` | user | The verbatim 13-rule operating contract (auditable agent rules) |
| `POST /analysis/security` | user | Structured evidence-grounded analysis for one event payload (full `SecurityEvent` shape or flat) → `SecurityAnalysis` + rendered `[SECURITY ANALYSIS]` report. **Recommend-only** — no defensive action is executed |
| `GET /analysis/{analysis_id}` | user | The full preserved audit record (rule 13): alert id, timestamp, raw evidence, tools used, TI sources, rules triggered, correlation results, assessment, risk, confidence, recommended action, human decision, final action. `404` when unknown |
| `GET /analysis/audit?limit=50` | user | Recent analysis audit records, newest first |
| `POST /analysis/{analysis_id}/feedback` | user | Record an analyst decision `{analyst, decision, notes}` with `decision ∈ {true_positive, false_positive, insufficient_evidence, unknown}` (rule 12, append-only) |
| `GET /analysis/feedback?limit=50` | user | The analyst feedback database, newest first |

## Infrastructure AI

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /infrastructure/telemetry` | user | One-shot REAL local telemetry snapshot (labeled `real` or `fallback` with explicit unavailable sections) |
| `POST /infrastructure/telemetry/emit` ⭐ | admin | Collect and publish a telemetry event on the bus |

## Coordinator dashboard & safe demo

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /coordinator/dashboard` | user | Aggregated HIVE Intelligence panel: 8 agent healths, bus stats, totals (events, active incidents, anomalies, critical risks, average risk), incidents, risk timeline, anomaly timeline, top risk factors, data quality, models |
| `POST /coordinator/demo` ⭐ | admin | Runs the fully-labeled **SIMULATION** end-to-end scenario (brute force → C2 → ethics → human approval → simulated block → knowledge → DS feedback). Body: `{approver}`. The response repeats `SIMULATION: true` and the simulation note |

## Core SOC risk validation endpoints

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /ml/risk` | user | Multi-layer 0–100 risk/confidence assessment with explanations; no action execution |
| `POST /ml/risk/feedback` | user | Store analyst verdict (`true_positive`, `false_positive`, `benign`, `unknown`) for continuous improvement |
| `GET /ml/risk/feedback?limit=50` | user | List recent validation feedback records |
| `POST /incident/respond` ⭐ | admin | Prepare response recommendation. High-impact containment returns `awaiting_human_validation` instead of executing |
| `POST /incident/respond/validate` ⭐ | admin | Analyst approval/rejection gate. Only `approve` executes the controlled response; `reject` records feedback and takes no containment action |

## Error conventions

- `401` — missing/invalid bearer token (all endpoints).
- `403` — authenticated but not admin (⭐ endpoints).
- `404` — unknown incident / verse not in stored dataset.
- `409` — lifecycle conflicts (e.g. approving a non-pending incident).
- `422` — validation failures (Pydantic) or out-of-range verse coordinates.
- `500` — unexpected failure; the response stays generic, the log carries
  the traceback. Degraded agents never produce `500`s — they return
  `degraded` payloads with explicit reasons instead.

## Example: the safe demo

```bash
TOKEN=$(curl -s -X POST localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<pass>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -X POST localhost:8000/coordinator/demo \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"approver":"demo-human-approver"}'
```

Stages returned: `pipeline` (×2 correlated events → `awaiting_approval`),
`human_approval` (records approver, runs simulated `block_ip`), and
`model_evaluation_after_feedback` (real metrics from validated labels).
