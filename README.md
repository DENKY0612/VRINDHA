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

There are no default credentials. While `vrin_SOC/database/users.json` is empty, the first `POST /register` creates the administrator.

See [`vrin_SOC/README.md`](vrin_SOC/README.md) and [`Vrin_TI/README.md`](Vrin_TI/README.md) for full documentation.
