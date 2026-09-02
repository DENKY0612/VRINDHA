# Security — HIVE Coordination Layer

How the coordination layer stays defensive, authorized, auditable, and
human-controlled. This extends — it does not relax — the existing SOC safety
controls (Zero Trust, intent analysis, authorization layer, Red Team
confirmation gate).

## 1. Authentication & authorization

- Every coordination endpoint requires a valid JWT
  (`Authorization: Bearer …`) issued by `POST /login` or the first-admin
  `POST /register`. Missing/invalid token ⇒ `401`; expired/disabled account
  ⇒ token rejected even if syntactically valid.
- **High-impact operations are admin-only** (non-admin ⇒ `403`):
  - `POST /commander/approve`, `POST /commander/reject` — the coordination-layer human approval gate.
  - `POST /incident/respond`, `POST /incident/respond/validate` — the core SOC response recommendation and analyst-validation gate.
  - `POST /coordinator/demo` — triggers the (fully simulated) demonstration.
  - `POST /knowledge/record` — validated knowledge is guarded.
  - `POST /infrastructure/telemetry/emit` — bus publication.
- No coordination endpoint accepts raw shell input; all payloads are
  validated Pydantic models or typed dicts.

## 2. The human approval gate

Defensive actions that are high-impact (block IP, isolate host, firewall
change, delete file, stop service, disable account) **never execute
automatically**:

1. SOC Analyst proposes an action only when the documented threshold is met
   (aggregate risk ≥ 0.5 over the 15-minute correlation **or** a confirmed
   malicious IOC) and an identifiable *source* address exists (victim
   addresses are never targeted).
2. Ethics & Compliance AI must pass the action (governing decision recorded).
3. The incident parks at `awaiting_approval`.
4. Only an admin `POST /commander/approve` — with `approver` identity,
   `conclusion`, and `justification` — releases the action. The response
   result is stored on the incident, and the incident trace records the
   approval.
5. Rejection closes the incident without any action.

The core SOC response engine follows the same pattern: `POST /incident/respond`
returns `awaiting_human_validation` for high-impact containment, and
`POST /incident/respond/validate` records the analyst verdict before executing
(or rejecting) the response. Analyst labels are stored in `alert_feedback` for
continuous improvement; unvalidated AI output is not treated as ground truth.

In this deployment the execution layer (`automation/actions.py::block_ip`)
runs in **simulation** for all backend modes (ufw/iptables/none): inputs are
validated (real IP syntax via `ipaddress`), the result is stored as
`status: "simulated"` with the exact action that would run, and **no real
firewall is mutated**. Enabling real execution is an operator configuration
decision outside the API surface.

### 2.5 JWT & session hardening

- Bearer tokens carry `iat`, `exp`, and a random `jti`, and are signed with the
  operator-provided `SECRET_KEY` (an ephemeral process key — with a startup
  warning — when unset, so tokens never survive a restart unconfigured).
- **Default token lifetime is 8 hours** (`480` minutes). It can only be raised
  deliberately via `ACCESS_TOKEN_EXPIRE_MINUTES`; a stolen token stops working
  at expiry, and disabling or deleting the account revokes its tokens
  immediately (`deps.get_current_user` re-checks the live user record).
- `POST /login` is throttled per client address (10 attempts/minute, sliding
  window) and the throttle map is size-bounded so rotating source addresses
  cannot exhaust memory. In multi-worker deployments, terminate TLS at a
  reverse proxy and add distributed rate limiting there.

### 2.6 IDS interface validation

`GET /incident/ids` and `GET /incident/idps` accept an `interface` query
parameter that reaches Suricata/Snort command lines. The value is
allowlist-validated (FastAPI `pattern`, plus `validate_interface` in
`tool_executor` as defense-in-depth for every caller, including the tcpdump,
snort, and tshark wrappers) so tool flags can never be injected through it.

## 3. Anti-fabrication guarantees

| Artifact | Guarantee |
|---|---|
| Threat intelligence | `malicious` is `true` only on a positive TI determination; TI unavailable ⇒ `malicious: null` + explicit `unavailable` status — absence of evidence is never reported as "clean" |
| Telemetry | `provenance.mode` is an enum (`real/simulated/mock/fallback`); fallback sections are explicit `{"status":"unavailable"}` entries |
| Model results | evaluation returns `insufficient_data` + empty metrics rather than invented numbers; empty-class means are `null` |
| Gita verses | served only from the stored 18-chapter dataset; out-of-range ⇒ 422, not-in-dataset ⇒ 404 with a "no fabricated verse" detail |
| Demo | every demo payload carries `SIMULATION: true` and `provenance.mode: simulated`; API responses repeat the simulation note |

## 4. Ethics boundaries (what the system will not do)

- **Judges actions, never users.** `EthicsAssessment` has no user-scoring
  field; no permanent moral ranking; output language never labels a person.
- **No religious profiling or coercion.** Gita guidance is optional
  (`gita_guidance: false` or declined at the user level ⇒ secular fallback),
  provided respectfully, and cited only from the verified dataset.
- **No unauthorized offensive capability.** Unauthorized access/theft ⇒
  `deny` + `high_risk_adharma`; testing on unconfirmed targets ⇒
  `require_authorization` with a safe alternative; authorized defensive
  work ⇒ aligned.
- **Legal references are guidance** (IT Act 2000, DPDP Act 2023, and
  international norms), explicitly labeled "not legal advice".
- Every ethics decision is written to the audit log (`ethics_audit_log`)
  with event id, action, authorization status, decision, and Gita reference.

## 5. Failure & abuse handling

- **Dead-letter queue:** any subscriber that raises is recorded
  (subscriber, event id, error) and isolated; delivery to other subscribers
  continues. The coordinator dashboard surfaces `failed` counts.
- **Degraded agents:** error streak ≥5 flips `health()` to `degraded`;
  `run_guarded` returns a `degraded` payload instead of crashing the
  pipeline. The system degrades, never pretends.
- **Brute-force protection:** the login endpoint keeps the existing
  per-client rate limit (10 attempts / 60 s ⇒ 429).
- **Data quality:** malformed events are rejected with a recorded reason
  (bad IP, future timestamp, invalid severity, schema failure, duplicate) —
  visible via `/data-science/status` and the dashboard.
- **No secrets in code or payloads.** Auth uses the existing `SECRET_KEY`
  environment requirement; coordination modules add no credentials.

## 6. Auditability

| Record | Store |
|---|---|
| Incident + full stage trace + approval + response | SQLite `coordination_incidents` |
| Ethics decisions | SQLite `ethics_audit_log` |
| Validated knowledge lessons / outcomes | SQLite `knowledge_lessons` / `incident_outcomes` |
| Dead-lettered agent failures | in-process bus (bounded; surfaced in `stats()`/dashboard) |
| Rejected raw events | in-process data-quality buffer (bounded; surfaced in API) |

The incident trace makes every `awaiting_approval → approve/reject` chain
reconstructable end-to-end: which events, what TI said, what the models
scored (with factors), what ethics decided, who approved, what ran
(simulated), and what was learned.
