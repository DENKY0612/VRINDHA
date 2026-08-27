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
| `GET /agents/health` | user | Health of all 7 coordination agents + bus stats |

## Commander (incidents & approval gate)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /commander/events` | user | Ingest an event into the full pipeline (human-approval gate applies) |
| `GET /commander/incidents?limit=50` | user | Recent incidents (newest first) |
| `GET /commander/incidents/{incident_id}` | user | Full incident: status, trace, proposed action, ethics, response |
| `POST /commander/approve?incident_id=...` ⭐ | admin | **Human approval** of the proposed high-impact action; body: `{approver, conclusion, justification}`. Runs the authorized (simulated) response, stores the validated knowledge lesson, feeds DS labels, closes the incident |
| `POST /commander/reject?incident_id=...` ⭐ | admin | Reject the proposal; body: `{approver, reason}`. No action is taken |

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

## Infrastructure AI

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /infrastructure/telemetry` | user | One-shot REAL local telemetry snapshot (labeled `real` or `fallback` with explicit unavailable sections) |
| `POST /infrastructure/telemetry/emit` ⭐ | admin | Collect and publish a telemetry event on the bus |

## Coordinator dashboard & safe demo

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /coordinator/dashboard` | user | Aggregated HIVE Intelligence panel: 7 agent healths, bus stats, totals (events, active incidents, anomalies, critical risks, average risk), incidents, risk timeline, anomaly timeline, top risk factors, data quality, models |
| `POST /coordinator/demo` ⭐ | admin | Runs the fully-labeled **SIMULATION** end-to-end scenario (brute force → C2 → ethics → human approval → simulated block → knowledge → DS feedback). Body: `{approver}`. The response repeats `SIMULATION: true` and the simulation note |

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
