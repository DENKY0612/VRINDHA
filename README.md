# 🛡️ Vrindha AI SOC

Vrindha is an ethical, defensive-first cybersecurity assistant with a CLI, FastAPI backend, browser dashboard, security-tool wrappers, SIEM-style logging, and lightweight ML analysis. Its policy layer uses intent analysis, authorization checks, and Bhagavad Gita-inspired guidance to keep active security operations controlled.

> **Core policy:** Red Team operations always require a separate confirmation. Blue Team responses may be automated for high-risk events. Use Vrindha only on systems you own or are explicitly authorized to test.

## Features

- **Central orchestrator:** classifies commands and routes them to security agents.
- **Red Team controls:** private/loopback targets by default, per-user confirmation, five-minute confirmation expiry, and no API auto-confirm bypass.
- **Blue Team workflows:** threat analysis, alerts, firewall simulation, IDS monitoring, endpoint checks, and response orchestration.
- **Tool wrappers:** nmap, whois, nikto, gobuster, dirb, amass, sublist3r, tcpdump, hashcat assistant, and related tools.
- **Authentication:** bcrypt password hashes and signed, expiring JWT access tokens.
- **Dashboard:** command center, logs, status, Gita guidance, tool checks, and Chart.js visualizations.
- **Logging and memory:** SQLite WAL storage, file logs, event correlation, and similar-case retrieval.
- **ML layer:** anomaly detection, rule-based risk scoring, threat prediction, and CSV data export.
- **Safety:** Dharma evaluation, intent detection, Zero Trust scoring, restricted public targets, command timeouts, and simulation fallbacks.

## Architecture

```text
User / Dashboard / API
          │
          ▼
Authentication → Brain Orchestrator
                    │
       ┌────────────┼─────────────┐
       ▼            ▼             ▼
 Intent &       Red/Blue       Planning &
 Dharma         Agents         Memory
       │            │             │
       └──── Safety & Authorization ────┐
                                        ▼
                              Safe Tool Executor
                                        │
                     ┌──────────────────┼───────────────┐
                     ▼                  ▼               ▼
                 Kali tools       SIEM / SQLite     ML analysis
```

Important directories:

```text
agents/       Recon, vulnerability, threat, SIEM, and endpoint agents
api/          FastAPI application and JWT authentication
automation/   Defensive response, firewall, IDS, and rootkit modules
core/         Brain, safety, authorization, Dharma, memory, and planning
dashboard/    Static SOC dashboard
database/     SQLite helpers and local user database
data/         Gita and cybersecurity knowledge data
ml/           Anomaly, risk, prediction, pipeline, and visualization modules
tools/        Safely wrapped external security tools
tests/        Security and regression tests
```

## Requirements

- Python 3.11 recommended
- Linux recommended; Kali Linux provides the fullest tool coverage
- Docker is optional
- External security tools are optional for development; missing tools return clear simulation or installation information

## Installation

```bash
git clone <repository-url>
cd vrindha
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration

Create the local environment file:

```bash
cp .env.example .env
```

At minimum, replace these values:

```dotenv
SECRET_KEY=<a-random-secret-of-at-least-32-characters>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<a-unique-password-of-at-least-12-characters>
```

Generate a suitable secret with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

The administrator is provisioned from the environment when it does not already exist. There are **no default credentials**. Keep `.env` private; it is excluded from Git.

Other important settings:

| Variable | Default | Purpose |
|---|---:|---|
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT lifetime |
| `CORS_ORIGINS` | empty | Comma-separated allowed browser origins; empty means same-origin only |
| `ALLOW_PUBLIC_TARGETS` | `False` | Enables active operations against public targets; keep disabled unless tightly controlled |
| `DEBUG` | `False` | Includes technical error details when enabled; never enable publicly |
| `API_HOST` / `API_PORT` | `0.0.0.0` / `8000` | API bind address and port |

## Running Vrindha

### CLI

```bash
source .venv/bin/activate
python3 main.py
```

Example:

```text
Vrindha> status
Vrindha> scan network 127.0.0.1
Vrindha> yes
Vrindha> detect threats malware attack from 192.168.1.50
Vrindha> show logs
Vrindha> exit
```

The CLI treats the local interactive operator as trusted, but Red Team commands still require a separate `yes` confirmation.

### API and dashboard

```bash
source .venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Open:

- Dashboard: <http://localhost:8000/dashboard/>
- API documentation: <http://localhost:8000/docs>
- Health/status: <http://localhost:8000/status>

Log in through the dashboard with the administrator configured in `.env`.

### Authenticated API example

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_CONFIGURED_PASSWORD"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -sS -X POST http://localhost:8000/command \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"command":"status"}'
```

A controlled scan requires two requests:

```bash
curl -sS -X POST http://localhost:8000/command \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"command":"scan network 127.0.0.1"}'

curl -sS -X POST http://localhost:8000/command \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"command":"yes"}'
```

Confirmations are isolated by authenticated username and expire after five minutes. The legacy `auto_confirm` field is rejected by the API.

## API endpoints

| Endpoint | Method | Authentication | Description |
|---|---|---|---|
| `/` | GET | Public | Basic service information |
| `/status` | GET | Public | Minimal status and container health check |
| `/login` | POST | Public | Exchange configured credentials for a JWT |
| `/gita/random` | GET | Public | Return a random guidance verse |
| `/gita/verse/{chapter}/{verse}` | GET | Public | Return a specific verse |
| `/command` | POST | Bearer JWT | Process a command |
| `/logs` | GET | Bearer JWT | Return recent logs; `limit` must be 1–500 |
| `/dashboard-data` | GET | Bearer JWT | Return dashboard status and visualization data |
| `/ml/anomaly` | POST | Bearer JWT | Analyze an event for anomalies |
| `/ml/risk` | POST | Bearer JWT | Calculate an event risk score |
| `/ml/predict` | GET | Bearer JWT | Generate heuristic threat predictions |
| `/ml/pipeline` | GET | Bearer JWT | Clean logs and export training CSV data |
| `/tools/verify` | GET | Bearer JWT | Report installed and missing external tools |
| `/dashboard/` | GET | Public | Serve the dashboard; data actions require login |

## Target authorization policy

By default:

- Loopback and private IP addresses are permitted after confirmation.
- Passive WHOIS lookups for valid public domains are permitted after confirmation.
- Active operations against public IP addresses and domains are denied.
- Government- and bank-related targets are explicitly denied by policy.
- Invalid or missing targets are denied rather than guessed.

`ALLOW_PUBLIC_TARGETS=True` is an operator-level escape hatch, not proof of authorization. Only enable it inside a deployment with documented scope controls and explicit permission from the target owner.

## Simulation versus real execution

Vrindha checks whether each external tool is installed. If a tool is unavailable—or an operation is intentionally implemented in safe mode—the response is marked as `simulated`. A simulation does **not** modify firewall rules, kill processes, or perform a real scan.

Some wrappers can execute installed command-line tools after authorization and confirmation. Commands use `shell=False`, bounded output, and a timeout. Review operating-system permissions and network scope before installing or enabling tools.

## Tests

Run the automated security and regression suite:

```bash
source .venv/bin/activate
python -m unittest discover -s tests -v
python -m compileall -q .
pip check
```

The suite currently covers password hashing, JWT validation, harmful-intent denial, target authorization, firewall IP validation, confirmation isolation, confirmation expiry, and auto-confirm prevention.

## Docker

Build the image:

```bash
docker build -t vrindha .
```

Run it with runtime credentials and persistent data:

```bash
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v vrindha-database:/app/database \
  -v vrindha-logs:/app/logs \
  vrindha
```

The container runs as an unprivileged user, does not embed credentials, and does not use Uvicorn development reload. Some network-security tools require additional Linux capabilities; grant only the minimum capability required for a documented defensive use case. Do not run the container as privileged merely to make every tool available.

## Security notes

- Sensitive endpoints require a valid Bearer token.
- Login attempts are rate-limited per process.
- Request bodies are limited to 1 MB when `Content-Length` is supplied.
- Dashboard log output is HTML-escaped to prevent stored XSS.
- Error tracebacks remain server-side unless explicitly enabled with `DEBUG=True`.
- SQLite uses WAL mode and a busy timeout for improved local concurrency.
- Dependency versions use bounded compatibility ranges.
- For multi-worker or multi-instance production, move confirmation state and login throttling to a shared store such as Redis.
- Put the API behind HTTPS and a production reverse proxy before exposing it to a network.

## Current limitations

- Risk scoring and prediction are primarily heuristic; they are not a substitute for a production SIEM or EDR.
- Several defensive actions are simulations by design.
- External Kali tools are not installed by Python dependencies.
- Confirmation state and login throttling are process-local.
- The included knowledge and Gita datasets are local project data; review them for your intended educational or production use.
- Docker behavior depends on the current Kali rolling base and should be validated and pinned in your deployment pipeline.

## Ethical use and disclaimer

Use Vrindha only for defensive work, education, authorized lab exercises, or assessments with explicit written permission. Never use it to access, disrupt, monitor, or test systems outside your approved scope.

This software is provided as an educational and defensive-security project without warranty. Operators are responsible for authorization, legal compliance, tool configuration, data protection, and actions taken through the system.
