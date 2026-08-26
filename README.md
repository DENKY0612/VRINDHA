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

cd vrin_SOC
uvicorn api.main:app --host 0.0.0.0 --port 8000
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

See [`vrin_SOC/README.md`](vrin_SOC/README.md) and [`Vrin_TI/README.md`](Vrin_TI/README.md) for full documentation.
