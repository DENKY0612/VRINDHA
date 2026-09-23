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
| Vrindha AI | `coordination/evidence_analysis.py` | Anti-hallucination, evidence-grounded analysis: FACT/INFERENCE/UNKNOWN separation, verified TI state, explainable risk+confidence, structured report, audit trail, feedback loop | Analyze + recommend only; **never executes** (see `docs/ANTI_HALLUCINATION.md`) |

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
| Core SOC feedback | SQLite `alert_feedback` (analyst true-positive / false-positive / benign / unknown verdicts for continuous improvement) |

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
|| Invalid raw event | Recorded rejection with reason; counted in data quality |

## 9. SecOps-Prime: Autonomous Security Command Generation

SecOps-Prime is the autonomous command-generation layer that translates natural-language
security intents into validated, executable commands. It bridges the gap between analyst
intent and tool execution while preserving the human-approval gate for high-impact actions.

### 9.1 How it works

1. **Intent parsing.** The analyst describes a goal in natural language (e.g. *"block
   all traffic from the IP that triggered the brute-force alert"*). SecOps-Prime parses
   the intent into a structured `SecurityCommand` with action, target, and parameters.
2. **Command validation.** The command is validated against a schema of allowed actions
   and parameter types. Invalid or unsafe commands are rejected with an explanation.
3. **Risk classification.** Each command is classified by impact level (`low`, `medium`,
   `high`, `critical`). High-impact commands (block IP, isolate host, firewall change)
   require explicit human approval before execution.
4. **Execution or queuing.** Low-impact commands (log query, status check) may execute
   automatically. High-impact commands enter the `awaiting_approval` queue and are
   surfaced to the admin for review.
5. **Audit trail.** Every generated command — whether executed, queued, or rejected —
   is logged with the originating intent, parsed structure, risk classification, and
   outcome.

### 9.2 Example

```text
Analyst: "Show me all failed SSH logins from 192.168.1.100 in the last hour"

SecOps-Prime:
  intent: query_logs
  action: search
  target: auth_log
  parameters:
    source_ip: 192.168.1.100
    event_type: ssh_failed
    time_range: 1h
  risk: low
  → executes immediately, returns matching log entries
```

```text
Analyst: "Isolate the compromised host on the DMZ"

SecOps-Prime:
  intent: isolate_host
  action: network_isolate
  target: host
  parameters:
    segment: dmz
    reason: compromised
  risk: critical
  → queued for admin approval (high-impact action)
```

### 9.3 Integration with the coordination layer

SecOps-Prime feeds generated commands into the Commander AI's approval workflow. The
Commander evaluates the command against active incidents, correlation data, and ethics
constraints before presenting it to the human admin. This ensures that autonomous
command generation never bypasses the defensive, human-controlled authority principle.

## 10. Daily Talk AI

Daily Talk AI is the conversational interface for casual, non-security interactions —
greetings, general knowledge questions, and lightweight assistance. It provides a
friendly entry point for users who are not performing security operations.

### 10.1 How it works

Daily Talk AI uses a three-tier response chain:

1. **Gemini API** (primary). The user's input is sent to the Gemini API for a
   natural-language response. This handles the widest range of queries with the most
   fluent output.
2. **Ollama** (fallback). If the Gemini API is unreachable or returns an error, the
   system falls back to a locally-hosted Ollama model. This ensures responses remain
   available even without external API access.
3. **Template fallback** (last resort). If both Gemini and Ollama are unavailable,
   the system uses pre-written template responses for common queries (greetings,
   help requests, status checks). Templates are explicitly marked as `FALLBACK` in
   the response metadata.

### 10.2 Response metadata

Every Daily Talk response includes metadata indicating which tier produced it:

```json
{
  "response": "Hello! How can I help you today?",
  "source": "gemini",
  "fallback": false
}
```

```json
{
  "response": "Hi there! What would you like to know?",
  "source": "template",
  "fallback": true
}
```

### 10.3 Casual greetings

For common greetings and pleasantries, Daily Talk AI uses a curated set of friendly
responses. These are handled at the template tier to minimize latency and API costs:

- *"Hello"* → *"Hello! How can I help you today?"*
- *"Good morning"* → *"Good morning! Ready to assist."*
- *"How are you?"* → *"I'm running smoothly, thanks for asking!"*
- *"What can you do?"* → *"I can help with security operations, answer questions, or just chat."*

## 11. AI Services Integration

The AI Services Integration layer provides a unified interface for all AI-powered
features across the platform. It abstracts the underlying model providers behind a
consistent API and manages the priority chain for response generation.

### 11.1 Priority chain

All AI requests follow a strict priority chain:

| Priority | Provider | When used |
|---|---|---|
| 1 (highest) | Gemini API | Default for all requests |
| 2 | Ollama (local) | When Gemini is unreachable or errors |
| 3 (lowest) | Templates | When both Gemini and Ollama are unavailable |

### 11.2 Request flow

```text
User request
    │
    ▼
AI Services Integration layer
    │
    ├─► Attempt Gemini API
    │     ├─► Success → return response (source: gemini)
    │     └─► Failure → log error, try next
    │
    ├─► Attempt Ollama (local)
    │     ├─► Success → return response (source: ollama)
    │     └─► Failure → log error, try next
    │
    └─► Use template fallback
          └─► Return response (source: template, fallback: true)
```

### 11.3 Provider configuration

Each provider is configured independently with its own timeout, retry policy, and
error-handling behavior:

- **Gemini API.** Configured with API key, model name, request timeout (default 30s),
  and max retries (default 2). Errors (timeout, rate limit, auth failure) trigger
  fallback to Ollama.
- **Ollama.** Configured with the local endpoint URL, model name, and request timeout
  (default 60s for local inference). Errors trigger fallback to templates.
- **Templates.** Static, always-available responses for common queries. No external
  dependencies; guaranteed to return a response.

### 11.4 Observability

Every AI request is logged with:
- The provider that ultimately served the response
- The number of fallback steps taken
- Latency per provider attempt
- Error details for failed attempts

This data feeds into the platform's observability dashboard, allowing operators to
monitor provider health, fallback rates, and response quality over time.
