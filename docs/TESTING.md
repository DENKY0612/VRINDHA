# Testing — HIVE Coordination Layer

The coordination layer is tested at four levels. **All tests are
deterministic, hermetic (no network, no real firewall), and run against an
isolated user store / in-memory bus so they never touch production data.**

## Run the suite

```bash
# from the repository root
vrin_SOC/.venv/bin/python -m pytest vrin_SOC/tests -q
```

Current state: **212 passed** in this sandbox with the full `python -m pytest -q` suite.

## Test map

### Unit

| File | Tests | Covers |
|---|---|---|
| `test_coordination_schemas.py` | 9 | Pydantic event/ethics/incident/model validation: malformed IP & timestamp & severity rejected, `Provenance.mode` enum, ethics model has **no user-scoring field**, incident trace append |
| `test_event_bus.py` | 9 | pub/sub delivery, wildcard, annotation merge-back, **dead-letter isolation of a failing subscriber**, correlation grouping, acknowledge/update, unsubscribe, stats accounting, pluggable transport |
| `test_data_science_ai.py` | 24 | ingest reject rules (bad IP/timestamp/severity/duplicate/future), **no feature leakage** (pre-store extraction excludes the event), stable feature names, anomaly determinism + explanation, **unavailable TI ≠ clean**, explainable risk factors, registry register/promote/retire + **conflict rejection** + **no silent production replacement**, **contamination guard** (unvalidated outcomes rejected), evaluation without labels ⇒ `insufficient_data` (never fabricated) |
| `test_ethics_dharma.py` | 20 | the 5-case decision matrix (theft ⇒ deny/high_risk + ASTEYA; authorized pentest ⇒ aligned; unknown-target scan ⇒ require_authorization; defensive ⇒ aligned; destructive ⇒ high_risk), verified-only Gita refs, **fabricated verse ⇒ None**, substring false-positive guard, high-impact ⇒ human approval, **no user moral scoring**, teach mode (educational, not shaming), audit log, ethics health (Gita KB shape) |

### Integration

| File | Tests | Covers |
|---|---|---|
| `test_coordination_integration.py` | 11 | agent-to-agent flow through the bus (Infrastructure → bus → Data Science), real-vs-fallback telemetry labeling, TI indicator extraction, **TI degrades without fabricating**, Data Science → SOC correlated investigation with `aggregate_risk`, correlation window, Knowledge stores **validated-only** lessons, **one broken agent never breaks the pipeline** |

### End-to-end (labeled simulation)

| File | Tests | Covers |
|---|---|---|
| `test_coordination_e2e.py` | 6 | the full scenario: suspicious events → Infrastructure → Commander → TI → Data Science → SOC → Risk → Ethics → **human approval** → defensive (simulated) response → Knowledge → DS feedback. Asserts the single shared incident, the approval gate existed, the `SIMULATION` label on every demo event, the closed incident with knowledge link, the fully reconstructable trace, the feedback reaching evaluation, and the **reject path** (no action). Also a **duplicate-event** rejection check. |

### API

| File | Tests | Covers |
|---|---|---|
| `test_api_coordination.py` | 13 | **every coordination endpoint requires auth** (401), **demo/approval require admin** (403), data-science health/models/ingest-reject/anomaly/risk, ethics deny + principles, **Gita verse verified + 422/404 (never fabricated)**, 18-chapter index, teach, commander incidents, coordinator dashboard shape (7 agents), demo returns a labeled simulation, infrastructure telemetry real/fallback label |

The API tests follow the existing `test_registration.py` pattern: an isolated
`AuthModule` (temp dir + dummy 48-char key) is swapped into `api.main`
**and** `api.deps` for the duration of each test, then restored — so the real
`users.json` is never touched. The auth dependency resolves the active auth
module from `api.main` at call time precisely so this harness (and the
pre-existing registration/teams tests) keep working unchanged.

## What the tests deliberately refuse to assert

- That a fabricated Gita verse exists (they assert the opposite: `None` / 404).
- That metrics are present when there are no labels (they assert
  `insufficient_data` + empty metrics).
- That a user received an ethical score (they assert the field does not
  exist).
- That a real firewall rule changed (the demo asserts `status: "simulated"`).

## Running the live demo manually

```bash
# start the API (SECRET_KEY required), then:
TOKEN=$(curl -s -X POST localhost:8000/login -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<pass>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:8000/coordinator/demo \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"approver":"demo-human-approver"}' | python3 -m json.tool
```

The demo is idempotent per-run (a fresh `run_id` per call) and always runs on
synthetic, `SIMULATION`-labeled data.
