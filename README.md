# Vrindha SOC

Ethical, defensive-first cybersecurity assistant with an independent threat-intelligence service.

| Directory | What it is |
|---|---|
| [`vrin_SOC/`](vrin_SOC/) | CLI, FastAPI backend, dashboard, agents, tools, SIEM, ML |
| [`Vrin_TI/`](Vrin_TI/) | Independent STIX 2.1 threat-intelligence service |
| [`presentation/`](presentation/) | Competition presentation |

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r vrin_SOC/requirements.txt -r Vrin_TI/requirements.txt
cp .env.example .env
# Set SECRET_KEY (and optionally ADMIN_USERNAME / ADMIN_PASSWORD)

python3 -m uvicorn vrin_SOC.api.main:app --host 0.0.0.0 --port 8000
```

- Dashboard: <http://localhost:8000/dashboard/>
- API docs: <http://localhost:8000/docs>

For a path-safe launcher from the repository root, install the SOC dependencies into `vrin_SOC/.venv` and run:

```bash
python3 -m venv vrin_SOC/.venv
vrin_SOC/.venv/bin/python -m pip install -r vrin_SOC/requirements.txt
VRINDHA_RUN_OPTION=2 ./vrin_SOC/run.sh
```

The launcher uses the same interpreter for dependency checks and Uvicorn, and accepts `API_HOST`, `API_PORT`, and `API_RELOAD` from the environment. There are no default credentials. While `vrin_SOC/database/users.json` is empty, the first `POST /register` creates the administrator.

## HIVE Intelligence (coordination layer)

`vrin_SOC/coordination/` adds a coordinated multi-agent layer on top of the
existing SOC: **Commander AI** (orchestration + incident lifecycle) over
**Infrastructure AI** (observe-only telemetry), **Threat Intelligence AI**
(IOC enrichment — never fabricated), **SOC Analyst AI** (triage, 15-minute
correlation, investigation), **Data Science AI** (validated ingest → features
with no leakage → interpretable anomaly → explainable weighted risk →
evaluated on human-validated labels only), **Knowledge AI** (validated
lessons only), and **Ethics & Compliance AI** (action-level Dharma
classification, verified Gita guidance, teach mode, ethics audit log).

Key properties:

- Agents communicate only through a shared, strongly-typed **event bus**
  (publish/subscribe/correlate/acknowledge, dead-letter isolation).
- **Human approval gate**: any high-impact defensive action (e.g. block IP)
  parks at `awaiting_approval`; only an admin can approve or reject, and in
  this deployment execution runs as a labeled **simulation**.
- Nothing is fabricated: TI absence ≠ "clean", missing labels ⇒
  `insufficient_data` (never invented metrics), Gita verses served only from
  the stored 18-chapter dataset.
- **No user moral scoring** — the ethics layer judges actions, never people;
  spiritual guidance is optional and verifiable.

Dashboard: the **HIVE Intelligence** pane (nav item, cyan badge) shows agent
health, risk/anomaly timelines, top risk factors, data quality, model status,
and incidents with Approve/Reject controls plus a Safe Demo button.

```bash
# run the labeled end-to-end simulation (admin JWT required)
curl -X POST localhost:8000/coordinator/demo \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"approver":"demo-human-approver"}'
```

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/RISK_VALIDATION.md`](docs/RISK_VALIDATION.md),
[`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md),
[`docs/DATA_SCIENCE.md`](docs/DATA_SCIENCE.md),
[`docs/API.md`](docs/API.md),
[`docs/MODEL_CARD.md`](docs/MODEL_CARD.md),
[`docs/SECURITY.md`](docs/SECURITY.md),
[`docs/TESTING.md`](docs/TESTING.md).

See [`vrin_SOC/README.md`](vrin_SOC/README.md), [`Vrin_TI/README.md`](Vrin_TI/README.md), and [`docs/import-structure.md`](docs/import-structure.md) for full documentation.
