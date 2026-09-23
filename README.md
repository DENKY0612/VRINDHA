# Vrindha SOC

Ethical, defensive-first cybersecurity assistant with an independent threat-intelligence service, autonomous security command generation, and conversational AI.

| Directory | What it is |
|---|---|
| [`vrin_SOC/`](vrin_SOC/) | CLI, FastAPI backend, dashboard, agents, tools, SIEM, ML, blockchain ledger, SecOps-Prime, Daily Talk AI |
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

## AI Services

Vrindha supports multiple AI backends for natural conversation and intelligent command generation:

| Service | Purpose | Priority |
|---|---|---|
| **Google Gemini API** | Daily Talk conversations, natural chat | Primary |
| **Ollama (qwen3.5:4b)** | Daily Talk fallback, local inference | Secondary |
| **Template responses** | Offline fallback | Last resort |

### Setting up Gemini API (optional)

```bash
export GEMINI_API_KEY="your-key-here"
```

Get your free key at: https://aistudio.google.com/app/apikey

## SecOps-Prime: Autonomous Security Command Generation

`vrin_SOC/core/secops_prime.py` translates natural language into precise, risk-aware security commands. Every command includes automatic risk assessment and throttling.

### How it works

```
Vrindha: scan vulnerabilities 192.168.1.1
→ [HIGH] Throttled Vulnerability Scan
→ sudo nmap -sV --script=vuln --max-rate 100 -T2 192.168.1.1 -oN vuln_scan.txt
→ Aggressive scan throttled to prevent DoS. Uses NSE vuln scripts.
```

### Supported commands

**Blue Team (Automated Defense):** `status`, `detect threats`, `show logs`, `block ip`, `firewall check`, `rootkit scan`, `ids monitor`, `anomaly detection`, `risk score`

**Red Team (Manual Approval):** `scan network`, `whois`, `scan vulnerabilities`, `nikto`, `gobuster`, `dirb`, `amass`, `sublist3r`, `tcpdump`, `wireshark`, `hashcat`, `ping sweep`, `full port scan`, `dns enum`, `ssl scan`, `mail scan`, `database scan`

**Intelligence:** `anomaly detection`, `dashboard`

**Hive:** `hive status`, `hive agents`, `hive snapshot`, `hive tasks`, `reap stale agents`

### Risk levels

| Level | Behavior |
|---|---|
| **LOW** | Fastest, most comprehensive commands (passive recon, firewall rules) |
| **MEDIUM** | Standard scans with default timing |
| **HIGH** | Automatic throttling (`--max-rate`, `-T2`, `-z` delays) to prevent DoS |

## Daily Talk AI

Conversational mode with Google Gemini API + Ollama integration. Supports:

- **Casual chat:** `wassup`, `watcha doin`, `sup`, `yo`, `hiya`, `heyyy`
- **Cybersecurity education:** 18+ topics with explanations and fun facts
- **Bhagavad Gita wisdom:** 701 verses for ethical guidance
- **Career advice:** SOC analyst, pentesting, certifications

```
Vrindha: daily
→ 🌸 Daily Talk Mode — Vrindha AI 🌸
→ 🤖 AI: ✅ Gemini | ✅ Ollama

Vrindha: wassup
→ "Hey! 🌸 Wassup? Chillin' here~ What's on your mind? ✨"
```

## Network Scanning Tools

All tools support IPv6, full flag coverage, and automatic throttling:

| Tool | File | Key Features |
|---|---|---|
| **Nmap** | `vrin_SOC/tools/nmap_tool.py` | SYN/TCP/UDP/ACK/NULL/FIN/XMAS, -sV, -O, -A, -p-, --top-ports, NSE scripts, IPv6, --max-rate throttling |
| **Nikto** | `vrin_SOC/tools/nikto_tool.py` | Web vuln scanner, Tuning, evasion, JSON output |
| **Amass** | `vrin_SOC/tools/amass_tool.py` | Passive/active/brute subdomain enumeration |
| **Sublist3r** | `vrin_SOC/tools/sublist3r_tool.py` | Multi-engine brute-force |
| **Gobuster** | `vrin_SOC/tools/gobuster_tool.py` | dir/dns/vhost/s3 enumeration |
| **Dirb** | `vrin_SOC/tools/dirb_tool.py` | Web directory scanner with delay |
| **Hashcat** | `vrin_SOC/tools/hashcat_tool.py` | Password cracking with GPU |
| **tcpdump** | `vrin_SOC/tools/tcpdump_tool.py` | Packet capture with BPF filters |
| **Wireshark** | `vrin_SOC/tools/wireshark_tool.py` | Tshark protocol analysis |
| **Snort** | `vrin_SOC/tools/snort_tool.py` | IDS/IPS with live capture |

## IPv6 Support

All scanning tools now support IPv6 targets (including compressed forms):

```bash
Vrindha: scan network 2606:4700:3031::ac43:b84e
Vrindha: scan vulnerabilities 2606:4700:3031::ac43:b84e
```

`vrin_SOC/coordination/` adds a coordinated multi-agent layer on top of the
existing SOC: **Commander AI** (orchestration + incident lifecycle) over
**Infrastructure AI** (observe-only telemetry), **Threat Intelligence AI**
(IOC enrichment — never fabricated), **SOC Analyst AI** (triage, 15-minute
correlation, investigation), **Data Science AI** (validated ingest → features
with no leakage → interpretable anomaly → explainable weighted risk →
evaluated on human-validated labels only), **Knowledge AI** (validated
lessons only), **Ethics & Compliance AI** (action-level Dharma
classification, verified Gita guidance, teach mode, ethics audit log), and
**Vrindha AI** (anti-hallucination, evidence-grounded security analysis:
FACT/INFERENCE/UNKNOWN separation, verified threat-intelligence state,
explainable risk + confidence, structured `[SECURITY ANALYSIS]` reports,
per-analysis audit trail, analyst feedback loop — recommend-only, never
executes), and the **Controlled Response Engine** (controlled autonomy: the
level of automation is proportional to the risk and reversibility of the
action — LOW → auto-monitor · MEDIUM → recommend → human approval · HIGH →
verify → policy → controlled containment → audit → rollback · CRITICAL →
multi-source verification → human approval / explicitly configured emergency
policy; critical-asset + allowlist protection, reversibility first, time
limits, rollback records, safe mode, immutable audit).

Key properties:

- Agents communicate only through a shared, strongly-typed **event bus**
  (publish/subscribe/correlate/acknowledge, dead-letter isolation).
- **Human approval gate**: every state-changing defensive action parks at
  `awaiting_approval` with an **ACTION PREVIEW**; only an admin can approve or
  reject, and in this deployment execution runs as a labeled **simulation**.
  The AI proposes the least destructive option (e.g. a 15-minute
  `temporary_ip_restriction` instead of a permanent `block_ip`) with a
  rollback record and expiry; a human may escalate with a justification.
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
[`docs/ANTI_HALLUCINATION.md`](docs/ANTI_HALLUCINATION.md),
[`docs/CONTROLLED_AUTONOMY.md`](docs/CONTROLLED_AUTONOMY.md),
[`docs/DATA_SCIENCE.md`](docs/DATA_SCIENCE.md),
[`docs/API.md`](docs/API.md),
[`docs/MODEL_CARD.md`](docs/MODEL_CARD.md),
[`docs/SECURITY.md`](docs/SECURITY.md),
[`docs/TESTING.md`](docs/TESTING.md).

See [`vrin_SOC/README.md`](vrin_SOC/README.md), [`Vrin_TI/README.md`](Vrin_TI/README.md), and [`docs/import-structure.md`](docs/import-structure.md) for full documentation.
