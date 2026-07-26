# 🛡️ Vrindha AI SOC System - Agentic AI Cybersecurity Platform

**World's First Ethical AI Cybersecurity System inspired by Bhagavad Gita** 🕉️

> **Core Principle:** Offensive actions (Red Team) → NEVER automatic | Defensive actions (Blue Team) → CAN be automated | AI acts as supervisor, not hacker

Built per **5 PDFs** - Complete integration without missing anything:
- ✅ MASTER SYSTEM BLUEPRINT (Controlled + Automated)
- ✅ 30-DAY VRINDHA BUILD PLAN (Cursor-Friendly)
- ✅ START UP Blueprint (Full-Stack Agentic AI)
- ✅ Work for AI ML (Intelligence Engine)
- ✅ Work for Data Science (Pattern Detection, Prediction)

---

## 🧠 System Architecture

```
Vrindha AI SOC System
│
├── 🧠 Core Brain (Orchestrator) - brain.py
│   ├── Intent Analyzer
│   ├── Dharma Engine (Gita Ethics)
│   ├── Authorization Layer
│   ├── Safety Layer
│   ├── Zero Trust Engine
│   ├── IAM Module
│   ├── Memory System (FAISS-ready)
│   ├── Planning Engine
│   └── Knowledge Base (CVE-style)
│
├── 🧠 Red Team Module (Manual Only - requires yes/no)
│   ├── Recon Agent - nmap, netdiscover, amass, sublist3r, whois
│   ├── Vulnerability Agent - nikto, openvas, searchsploit
│   ├── Exploitation Assistant (No auto execution) - metasploit suggestion only
│   └── Web Tools - gobuster, dirb, tcpdump, hashcat (strict control), wireshark
│
├── 🧠 Blue Team Module (Automated)
│   ├── Threat Detection - attack/breach/malware keywords, risk LEVELS
│   ├── Response Engine - block_ip, kill_process, send_alert (only HIGH risk auto)
│   ├── Endpoint Protection - rkhunter, chkrootkit, clamav
│   ├── IDS Monitor - snort, suricata (alert only, no auto-block)
│   ├── Firewall Auto - fail2ban, ufw (after 5 failed threshold)
│   └── Rootkit Scanner - automated scan
│
├── 🧠 Tool Layer - Kali Tool Wrappers (safe execution, timeout 10s)
│   └── nmap, whois, nikto, amass, sublist3r, gobuster, dirb, tcpdump, hashcat, wireshark, snort, netstat...
│   └── Installation module: install_tool() with permission ask
│   └── Verification: verify_all_tools()
│
├── 🧠 SIEM & Logging
│   ├── File logging: logs/log.txt + DB logging: database/vrindha.db
│   └── SIEM Agent - correlation, timeline, alerts
│
├── 🧠 Safety & Authorization Layer
│   ├── Dharma Engine: evaluate_action() -> allow/deny/warn + gita_verse
│   ├── Intent Analyzer: safe/suspicious/malicious
│   └── Gita Engine: 701 verses, get_verse, search, random, ethical_guidance
│
└── 🧠 Super Intelligence Layer
    ├── Memory System - save/retrieve_similar past cases
    ├── Planning Engine - breaks tasks: scan->detect->prioritize->fix
    ├── Self-Learning Loop - Observe->Analyze->Learn->Improve
    ├── Multi-Agent Reasoning - Recon->Vuln->Threat->Response->Log
    └── Knowledge Base - CVE-style vulns, attack patterns, defenses

---

## 📦 Tool Stack (Full from PDFs)

**Red Team Manual:**
- Recon: nmap, amass, sublist3r, netdiscover, whois
- Web: gobuster, dirb, nikto
- Network: wireshark/tshark, tcpdump
- Credential: hashcat (suggestion only, strict control)
- Guidance: recon-ng, metasploit, burpsuite, hydra, john, openvas, searchsploit

**Blue Team Automated:**
- IDS: snort, suricata
- Endpoint: rkhunter, chkrootkit, OSSEC, clamav
- Firewall: fail2ban, ufw
- SIEM: Wazuh (simulated + log correlation)

**Start at:** nmap → nikto → wireshark → fail2ban, then expand per blueprint

---

## 🚀 Quick Start

### 1. CLI Mode (Per Day 2-4 Blueprint)
```bash
cd vrindha
python3 main.py
```
Commands:
```
Vrindha> hello
Vrindha> status
Vrindha> scan network 127.0.0.1
> [Confirmation required per Red Team safety] Do you want to proceed? (yes/no)
Vrindha> yes
Vrindha> whois google.com
Vrindha> yes
Vrindha> scan vulnerabilities 127.0.0.1
Vrindha> detect threats malware attack from 192.168.1.50
Vrindha> show logs
Vrindha> block ip 192.168.1.100
Vrindha> exit
```

### 2. API Mode (Per Day 24-26)
```bash
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
# Open http://localhost:8000/docs for Swagger
# Dashboard at http://localhost:8000/dashboard/
```

Test API:
```bash
curl -X POST http://localhost:8000/command -H "Content-Type: application/json" -d '{"command":"status"}'
curl -X POST http://localhost:8000/command -H "Content-Type: application/json" -d '{"command":"scan network 127.0.0.1"}'
curl http://localhost:8000/logs
curl http://localhost:8000/gita/random
```

### 3. Docker (Per Deployment Prompt)
```bash
docker build -t vrindha .
docker run -p 8000:8000 vrindha  # API
docker run -it vrindha python3 main.py  # CLI
```

---

## 🔐 Safety Features (Per Blueprints)

- **Red Team NEVER automatic:** Always asks "Do you want to proceed? (yes/no)" + authorization check
- **Blue Team CAN be automated:** HIGH risk auto-blocks IP after 5 failed, sends alerts
- **Dharma Engine:** Evaluates every action for ethics (Dharma vs Adharma per Gita)
  - Unauthorized hacking → DENY + Gita teaching: "True strength lies in protecting, not exploiting"
  - High-risk tools (metasploit, hashcat) → WARN + requires justification
  - Defensive/learning → ALLOW + "Performing duty aligned with protection"
- **Zero Trust:** Validates every command, assigns trust score 0-100
- **Tool Execution:** Checks existence, subprocess safely, timeout 10s, no crash
- **Logging:** Every action logged to file + SQLite

---

## 🕉️ Dharma & Gita Integration

- **data/gita.json:** 701 verses from 18 chapters, each with tags: dharma, self_control, knowledge, non_violence, duty, protection
- **Gita Engine APIs:** get_verse(ch, verse), search_by_keyword(), get_random_verse(), get_ethical_guidance(action)
- **Dharma Flow:** User Command → Intent Analysis → Dharma Engine → Decision: Allow/Warn/Deny → Gita verse + teaching
- **Educational Response:** When denying unsafe: blocks + shows teaching inspired by Gita

Example:
```
User: Hack this website
AI: {decision: deny, reason: Unauthorized access violates ethical principles, message: Use your skills to protect, not harm., gita_verse: {chapter:2, verse:47, text: Karmanye...}}
```

---

## 📊 AI/ML & Data Science Intelligence Layer

Per **work for AI ML.pdf** and **work for data science.pdf** - She/He becomes Intelligence Engine:

**Phase 1 - Data Foundation:** Collect logs from Vrindha (commands, outputs, scans, threats) → JSON → Pandas CSV/SQLite via ml/data_pipeline.py

**Phase 2 - Analysis:** Frequent commands, repeated IPs, suspicious activity, most common ports, most active time

**Phase 3 - Anomaly Detection (Core AI):** Scikit-learn IsolationForest, K-Means → Returns {event, anomaly_score: 0.92, status: suspicious}

**Phase 4 - Risk Scoring (Startup Core Feature):** {ip: 192.168.1.10, risk_score: 85, reason: multiple failed attempts + unusual port}

**Phase 5 - Prediction:** Historical logs + behavior trends → Predict future threats (TensorFlow/PyTorch placeholder)

**Phase 6 - Dashboard Intelligence:** Attack trends, risk over time, alerts - Graphs via Chart.js in dashboard/index.html + ml/visualization.py

**Integration Flow:**
```
Vrindha System
     ↓
Logs + Data → Her ML Models (Anomaly, Risk, Prediction)
     ↓             ↓
SIEM Agent   Risk Scores → Brain (Decision Making)
```

---

## 📅 30-Day Plan Coverage

- ✅ Week1 Day1-7: Project setup, CLI, Brain, ReconAgent dummy, connect, cleanup
- ✅ Week2 Day8-14: Nmap tool, test, connect to agent, better JSON output, Whois tool, extend Brain commands, cleanup testing
- ✅ Week3 Day15-21: VulnAgent, connect, ThreatAgent, Logging file, connect logging, SIEM Agent, code review
- ✅ Week4 Day22-30: Automation block_ip/kill_process, trigger HIGH risk, FastAPI setup, /command endpoint, test API, SQLite logs(id,command,result,timestamp), connect DB, simple HTML dashboard, final integration CLI+API+Agents+Tools
- ✅ Bonus: Installation module, multi-tool installer, verification, advanced recon (amass, sublist3r, recon-ng), web testing (gobuster, dirb), network sniffing (tcpdump), credential testing (hashcat strict), Blue additional (ids, rootkit, firewall), Dharma Engine, Gita Engine

---

## 🌐 API Endpoints (Per Startup Blueprint)

- POST /command → AI command
- GET /logs → fetch logs
- GET /status → system status
- POST /login → JWT authentication
- GET /dashboard-data → viz + logs + status
- GET /gita/random, /gita/verse/{ch}/{v}
- POST /ml/anomaly → anomaly detection
- POST /ml/risk → risk scoring
- GET /ml/predict → threat prediction
- GET /ml/pipeline → data pipeline + CSV export
- GET /tools/verify → tool stack verification
- GET /dashboard/ → static SOC dashboard

---

## 🧠 Agentic Behavior

Per blueprints: Agent Collaboration Prompt - Agents share outputs, escalate critical threats, avoid redundant

Flow: **Recon → Vuln → Threat → Response → Log** → Memory → Planning → Knowledge Base → Dashboard

---

## 🐳 Deployment

- Dockerfile provided (Kali base, installs tools, requirements, exposes 8000, healthcheck)
- .env.example for environment variables
- Future: AWS/VPS + Nginx + HTTPS per deployment prompt

---

## ⚠️ Ethics & Safety

- Never perform unauthorized attacks - only approved scope
- Log all activities for audit
- Follow Zero Trust, Least Privilege
- Prioritize defense over exploitation
- Prefer simulation over real attack when possible
- Never execute destructive payloads

---

## 👥 Team Structure (Ideal Startup)

- You → Backend + AI System (Vrindha) - CLI, Agents, API, Logging, Tool Stack
- Data Science Student → Intelligence + ML - Data pipeline, anomaly, risk scoring, viz, prediction
- AI/ML Engineer → Intelligence Layer - Data foundation, analysis, anomaly, risk, prediction, dashboard graphs
- Frontend → Dashboard (React/HTML) - Provided in dashboard/

Final Result:
- Without team: Tool-based assistant
- With team: AI-powered cybersecurity platform (startup-level)

---

## 📄 License & Disclaimer

Educational use only. Use only on systems you own or have explicit permission to test. Authors not responsible for misuse. Dharma protects those who protect Dharma.

---

## 🔥 Final Result After Integration

You have:
✅ AI command assistant
✅ Kali tool integration (real wrappers + simulation fallback)
✅ Multiple agents (Recon, Vuln, Threat, SIEM, Exploit Assist, Network Recon, Endpoint)
✅ Logging + SIEM (file + SQLite + correlation + timeline)
✅ Automation basics (block_ip, kill_process, alert, firewall, ids, rootkit)
✅ API backend (FastAPI + JWT + CORS + docs)
✅ Simple dashboard + advanced SOC dashboard with Chart.js (Attack trends, Ports, Risk, Logs, Alerts, Gita, ML, Tool verify)
✅ Dharma + Gita System (701 verses JSON, ethical engine, intent analysis)
✅ AI/ML Intelligence (data pipeline Pandas, anomaly IsolationForest, risk scoring, prediction TF/PT placeholder, visualization)
✅ Super Intelligence Layer (Memory FAISS-ready, Planning Engine, Self-Learning, Multi-Agent Reasoning, Knowledge Base)

**That's a real MVP cybersecurity AI system - startup-ready product, not just a project.** 🚀
