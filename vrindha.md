# 🛡️ Vrindha — Project Overview

> A one-stop, easy-to-explain guide to the entire **Vrindha SOC** project.
> Read this top to bottom and you'll be able to explain the project to anyone.

---

## 1. In one line

**Vrindha is an ethical, defensive-first cybersecurity assistant (a Security
Operations Center, or *SOC*) that detects threats, investigates them, and
recommends safe responses — but never takes destructive action without a
human's approval.**

Think of it as a **team of AI security analysts working together on your
computer**, with strict safety rules, full transparency, and an unchangeable
audit trail.

---

## 2. The big idea

Cybersecurity tools are usually either:

- **Manual** — a human analyst stares at logs all day (slow, tiring), or
- **Fully automatic** — a script blocks things on its own (dangerous if it's wrong).

Vrindha takes the middle path: **controlled autonomy**.

- The AI **watches, detects, correlates, and investigates** automatically.
- For low-risk events it **monitors on its own**.
- For risky actions (blocking an IP, isolating a machine), it **proposes the
  safest option and waits for a human admin to approve**.
- Every step is **explained**, **labeled as real or simulated**, and **recorded
  permanently** so it can never be secretly altered.

The project also embeds an **ethics layer** inspired by the *Dharma* principles
of the Bhagavad Gita — the AI judges *actions* (is this response justified and
reversible?), never people.

---

## 3. The two main parts

| Folder | Name | Role |
|---|---|---|
| [`vrin_SOC/`](vrin_SOC/) | **Vrindha SOC** | The main app: CLI, FastAPI backend, web dashboard, AI agents, automation, ML, blockchain ledger. |
| [`Vrin_TI/`](Vrin_TI/) | **Vrin Threat Intelligence** | A separate, independent service that stores and enriches threat data (STIX 2.1 standard). It tells the SOC *"is this IP/hash/domain known-bad?"*. |

They talk to each other over an authenticated API. `Vrin_TI` is **defensive
only** — it can recommend alerts but never runs scans, exploits, or firewall
changes.

---

## 4. How a security event flows (the core workflow)

```
   A security event happens
   (real sensor data OR a labeled SIMULATION)
            │
            ▼
  ┌──────────────────────────┐
  │  Data Science AI         │  Validates & cleans the data.
  │  (quality check)         │  Bad data is rejected, never faked.
  └──────────────────────────┘
            │
            ▼
  ┌──────────────────────────┐
  │  Commander AI            │  Opens an "incident" and orchestrates
  │  (the coordinator)       │  all the other agents.
  └──────────────────────────┘
            │
   ┌────────┼───────────────────────────┐
   ▼        ▼                           ▼
┌──────┐ ┌──────────────┐      ┌──────────────────┐
│Threat│ │ Data Science │      │ SOC Analyst AI   │
│Intel │ │ AI: anomaly +│      │ triage, correlate│
│AI: is│ │ risk score   │      │ events over 15   │
│this  │ │ (explained)  │      │ minutes, recommend
│IOC   │ └──────────────┘      │ response         │
│known?│                       └──────────────────┘
└──────┘                                │
            ▼                           ▼
  ┌──────────────────────────┐
  │ Ethics & Compliance AI   │  Classifies the *action* by Dharma
  │ + Vrindha AI (anti-      │  rules. Separates FACT vs INFERENCE
  │ hallucination)           │  vs UNKNOWN — never makes things up.
  └──────────────────────────┘
            │
            ▼
   Is a risky action needed?
   ┌─────────────────────┐        ┌──────────────────────────┐
   │ NO  → keep monitoring│        │ YES → park at             │
   │ (status: open/closed)│        │ "awaiting_approval" and   │
   └─────────────────────┘        │ show an ACTION PREVIEW    │
                                  └──────────────────────────┘
                                               │
                                  ┌────────────┴────────────┐
                                  ▼                         ▼
                          Human APPROVES            Human REJECTS
                                  │                         │
                  Run the *least destructive*,     No action taken;
                  *reversible* response (e.g.       incident marked
                  15-min temporary block, in        rejected.
                  SIMULATION mode). Record the
                  lesson + label for learning.
                                  │
                                  ▼
                  Everything is hashed into the
                  BLOCKCHAIN LEDGER (tamper-proof).
```

**Key points of the flow:**

1. **Nothing is fabricated.** If threat intel is unreachable, the result is
   `unavailable` — *not* "clean." Missing data is reported, never invented.
2. **Related events within 15 minutes are grouped** into one incident
   (correlation), so one attack isn't treated as ten separate alerts.
3. **Humans are always in control** of state-changing actions.

---

## 5. The AI agents (the "team")

All agents live in [`vrin_SOC/coordination/`](vrin_SOC/coordination/) and talk
only through a shared **event bus** (a typed publish/subscribe message system)
so they stay loosely coupled.

| Agent | What it does |
|---|---|
| **Commander AI** | The boss. Manages the incident lifecycle, correlates events, runs the approval gate. Orchestrates but executes nothing destructive itself. |
| **Infrastructure AI** | Collects local telemetry — CPU, memory, disk, network, running processes. *Observe only.* |
| **Threat Intelligence AI** | Pulls out indicators (IPs, hashes, domains) and checks them against `Vrin_TI`. Lookup only; degrades to `unavailable` instead of guessing. |
| **Data Science AI** | The full ML pipeline: validate → clean → features → **anomaly detection** → **explainable risk score** → evaluate → feedback. Analyzes only; never acts. |
| **SOC Analyst AI** | Triage, 15-minute correlation, investigation summaries, recommendations. Recommends; humans approve. |
| **Knowledge AI** | Stores **validated** lessons from past incidents so the system learns from real, human-confirmed outcomes. |
| **Ethics & Compliance AI** | Judges each *action* (not the user) against Dharma principles, serves verified Gita guidance, keeps an ethics audit log. |
| **Vrindha AI** | The anti-hallucination brain. Separates **FACT / INFERENCE / UNKNOWN**, gives risk + confidence, writes structured `[SECURITY ANALYSIS]` reports with an audit trail. **Recommends only — never executes.** |
| **Controlled Response Engine** | Decides how much automation is allowed based on risk & reversibility (see below). |

### Controlled autonomy levels

| Risk level | What the system may do |
|---|---|
| **LOW** | Auto-monitor |
| **MEDIUM** | Recommend → wait for human approval |
| **HIGH** | Verify → check policy → controlled containment → audit → rollback |
| **CRITICAL** | Multi-source verification → human approval / explicit emergency policy |

Safety features: critical-asset and allowlist protection, **reversibility
first**, action time limits, rollback records, safe mode, and an immutable
audit log.

---

## 5b. SecOps-Prime: Autonomous Security Command Generation

Location: [`vrin_SOC/core/secops_prime.py`](vrin_SOC/core/secops_prime.py)

SecOps-Prime translates natural language security objectives into precise,
pipeline-ready commands with automatic risk assessment and throttling.

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

### AI-powered command generation

SecOps-Prime uses **Google Gemini API** (primary) or **Ollama qwen3.5:4b**
(fallback) to generate context-aware commands. When AI is unavailable, it
falls back to rule-based parsing with the same risk assessment.

---

## 5c. Daily Talk AI

Location: [`vrin_SOC/core/daily_talk.py`](vrin_SOC/core/daily_talk.py)

Conversational mode for casual chat, cybersecurity education, and Gita wisdom.

### AI Services (Priority Order)

| Priority | Service | Status |
|----------|---------|--------|
| 1st | **Google Gemini API** | Primary (if API key set) |
| 2nd | **Ollama qwen3.5:4b** | Fallback |
| 3rd | **Template responses** | Last resort |

### Casual greetings supported

```
"wassup" → "Hey! 🌸 Wassup? Chillin' here~!"
"watcha doin" → "Sup! 🌸 Just hanging out~ Whatcha doin?"
"sup" → "Hey there! 😊 I'm doing great!"
"yo" → "Hii! 👋 Just vibing in Daily Talk mode~"
"hiya" → "Hey! 💕 Happy to see you!"
"yooo" → "Yo yo! 🌸 Nothing much, just being awesome~"
"heyyy" → "Hii! 🌸 Ready to chat or learn something cool?"
```

### Features

- **Casual chat:** Natural conversation matching user energy
- **Cybersecurity education:** 18+ topics with explanations and fun facts
- **Bhagavad Gita wisdom:** 701 verses for ethical guidance
- **Career advice:** SOC analyst, pentesting, certifications

### Setup

```bash
export GEMINI_API_KEY="your-key-here"
```

Get your free key at: https://aistudio.google.com/app/apikey

---

## 6. The supporting building blocks

- **Core Brain** ([`vrin_SOC/core/`](vrin_SOC/core/)) — intent analysis,
  authorization, Zero-Trust checks, safety layer, Dharma & Gita engines,
  memory and planning. Guards every CLI/API command.
- **Red-team tools** ([`vrin_SOC/tools/`](vrin_SOC/tools/),
  [`vrin_SOC/agents/`](vrin_SOC/agents/)) — *defensive use only* wrappers for
  scanners like nmap, nikto, gobuster, wireshark, snort, hashcat, etc., with a
  verifier and installer. These support authorized testing/learning.
- **Automation** ([`vrin_SOC/automation/`](vrin_SOC/automation/)) — the *only*
  execution path for responses: firewall actions, IDS monitoring, rootkit
  scanner. Inputs are validated and actions run in **simulation mode** unless
  an operator explicitly configures real enforcement.
- **Autonomous subsystem** ([`vrin_SOC/autonomous/`](vrin_SOC/autonomous/)) —
  goals, planner, observer, executor, verifier, recovery, scheduler, state
  management for long-running autonomous tasks.
- **Machine Learning** ([`vrin_SOC/ml/`](vrin_SOC/ml/)) — anomaly detector, data
  pipeline, prediction model, weighted risk scoring, visualization.
- **Hive** ([`vrin_SOC/hive/`](vrin_SOC/hive/)) — the registry/coordinator that
  tracks all agents and their health.
- **Database** ([`vrin_SOC/database/`](vrin_SOC/database/)) — SQLite storage for
  users, incidents, knowledge lessons, ethics audit log, and analyst feedback.
- **Web Dashboard** ([`vrin_SOC/dashboard/`](vrin_SOC/dashboard/)) — HTML/JS UI
  with a **HIVE Intelligence** pane: agent health, risk timelines, top risk
  factors, data quality, model status, and **Approve/Reject** controls.

---

## 7. The blockchain ledger (integrity anchor)

Location: [`vrin_SOC/blockchain/`](vrin_SOC/blockchain/).

A **local, dependency-free mini-blockchain** (pure Python, no network, no
daemon). It is **not a cryptocurrency** — it is a tamper-proof audit log.

- Each block stores a small **summary** of an event (an approval, an ethics
  decision, a lesson) and is linked to the previous block via **SHA-256**.
- Blocks are **mined** with a lightweight proof-of-work (default difficulty 2,
  under a millisecond).
- `verify()` recomputes every hash; if anyone retro-edits a record, the chain
  reports **exactly which block was changed**.
- Reads (`GET /blockchain`, `/verify`) are open; appending
  (`POST /blockchain/add`) requires a SOC login.

This makes the record of **what happened and in what order** unforgeable,
without storing sensitive raw data.

---

## 8. Safety, ethics & anti-hallucination principles

These are the project's defining values:

1. **Defensive-first.** Everything protects; nothing attacks unauthorized targets.
2. **Human approval gate.** Risky actions always pause for an admin, with an
   ACTION PREVIEW; the AI proposes the **least destructive, reversible**
   option (e.g. a 15-minute temporary IP restriction instead of a permanent
   block).
3. **No fabrication.** Threat-intel absence ≠ "clean." Missing labels ⇒
   `insufficient_data`. Gita verses come only from the stored 18-chapter dataset.
4. **Explainability.** Every anomaly/risk score ships with the factors that
   produced it in plain language.
5. **Judges actions, never people.** The ethics layer classifies the *action*
   (Dharma); there is no user moral scoring. Spiritual guidance is optional
   and verifiable.
6. **Real vs simulated is always labeled.** Every payload carries a provenance
   mode: `real`, `simulated`, `mock`, or `fallback`.
7. **Graceful degradation.** A failing agent is marked `degraded` and sent to a
   dead-letter queue; the pipeline keeps going and never pretends success.

---

## 9. Tech stack

- **Language:** Python 3 (standard library + FastAPI/Uvicorn backend).
- **API:** FastAPI (auto docs at `/docs`), JWT auth.
- **Frontend:** Lightweight HTML/CSS/JS dashboard (no heavy framework).
- **Storage:** SQLite (incidents, knowledge, audit) + JSON files (users,
  ledger, Gita dataset).
- **ML:** scikit-learn-style pipeline for anomaly detection & risk scoring.
- **AI:** Google Gemini API (primary), Ollama qwen3.5:4b (fallback), template
  responses (offline).
- **Threat intel:** STIX 2.1, optional integrations (MISP, OpenCTI,
  VirusTotal, AbuseIPDB, NVD, TAXII, Suricata/Zeek logs).
- **Blockchain:** Custom local SHA-256 chain, standard library only.
- **Testing:** pytest (broad suite covering coordination, controlled response,
  blockchain, ethics, security, registration, and more).
- **Network:** Full IPv6 support across all scanning tools.

---

## 10. Running it (quick start)

```bash
# from the repository root
python3 -m venv .venv && source .venv/bin/activate
pip install -r vrin_SOC/requirements.txt -r Vrin_TI/requirements.txt
cp .env.example .env        # set SECRET_KEY (and optional admin creds)

python3 -m uvicorn vrin_SOC.api.main:app --host 0.0.0.0 --port 8000
```

- **Dashboard:** http://localhost:8000/dashboard/
- **API docs:** http://localhost:8000/docs
- The first `POST /register` (while the user store is empty) creates the administrator.

Other handy entry points:

```bash
# CLI chat / assistant
python3 -m vrin_SOC

# Blockchain demo (build → verify → tamper → detect)
python3 -m vrin_SOC.blockchain demo

# Labeled end-to-end coordination demo (admin JWT required)
curl -X POST localhost:8000/coordinator/demo \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"approver":"demo-human-approver"}'
```

---

## 11. Repository map

```
Vrindha_SOC/
├── vrin_SOC/            # Main SOC application
│   ├── agents/          # Red/blue team agents (defensive use)
│   ├── api/             # FastAPI app, auth, routes (incl. blockchain)
│   ├── automation/      # Response execution (firewall, IDS, scanners)
│   ├── autonomous/      # Goal/planner/executor autonomous subsystem
│   ├── blockchain/      # Local tamper-proof audit ledger
│   ├── coordination/    # HIVE multi-agent layer (Commander + 8 AIs)
│   ├── core/            # Brain: intent, auth, Zero-Trust, Dharma, safety
│   ├── dashboard/       # Web UI (HTML/CSS/JS)
│   ├── data/            # Gita dataset, knowledge base, training data
│   ├── database/        # SQLite models & user store
│   ├── hive/            # Agent registry / coordinator
│   ├── ml/              # Anomaly detection + risk scoring
│   ├── tools/           # Wrapped security tools (nmap, nikto, …)
│   └── tests/           # pytest suite
├── Vrin_TI/             # Independent STIX 2.1 threat-intel service
├── docs/                # Architecture & design documents
├── presentation/        # Competition presentation (PPTX + builder)
└── README.md
```

---

## 12. The 30-second elevator pitch

> **Vrindha is an AI-powered Security Operations Center that acts like a team
> of ethical security analysts. It continuously watches a system, uses machine
> learning and threat intelligence to spot and investigate attacks, correlates
> related events, and explains every finding in plain language — clearly
> separating facts from guesses. SecOps-Prime translates natural language into
> precise, risk-aware security commands with automatic throttling. Daily Talk AI
> provides friendly, kawaii conversation powered by Google Gemini API + Ollama.**
>
> **It never fabricates data and never takes risky action on its own: low-risk
> events are monitored automatically, while anything destructive pauses for a
> human's approval, defaulting to the most reversible response. An ethics layer
> judges each action, and every decision is anchored in a local blockchain
> ledger so the audit trail can never be secretly altered.**

---

*For deeper detail, see [`README.md`](README.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/CONTROLLED_AUTONOMY.md`](docs/CONTROLLED_AUTONOMY.md),
[`docs/ANTI_HALLUCINATION.md`](docs/ANTI_HALLUCINATION.md),
[`docs/SECURITY.md`](docs/SECURITY.md), and
[`vrin_SOC/blockchain/README.md`](vrin_SOC/blockchain/README.md).*
