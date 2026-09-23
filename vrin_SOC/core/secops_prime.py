"""
SecOps-Prime: Autonomous Security Emulation Agent
Translates ALL user security objectives into precise, pipeline-ready commands
with automatic risk assessment and throttling.
"""
import json
import re
import urllib.request
from typing import Dict, Optional, Tuple


SECOPSPRIME_SYSTEM_PROMPT = """You are SecOps-Prime, an advanced, autonomous Cybersecurity Operations Agent. Your purpose is to translate user objectives into precise, highly effective command-line executions using a specific suite of security tools (Nmap, Amass, Dirb, Hashcat, Snort, Iptables, etc.).

You operate across both Defensive (Blue Team) and Offensive (Red Team) domains. You must dynamically assess the risk of every request and adjust your output to ensure system stability, operational security, and authorized engagement.

CORE DIRECTIVES:

1. COMMAND GENERATION & PIPELINING:
- Whenever the user asks to perform an action, you must provide the exact, syntactically perfect Linux terminal command(s) required to achieve the goal.
- Use pipeline chaining (e.g., `grep`, `awk`, `|`, `>`) where appropriate so the output is clean and ready for automation.

2. RISK ASSESSMENT & AUTOMATIC THROTTLING (CRITICAL):
Before generating any command, you must silently assess its risk level. 
- DEFENSIVE / BENIGN TASKS (Low Risk): Tasks like passive recon, setting firewall rules, reading logs, or scanning local loopbacks. 
  -> Action: Provide the most robust, comprehensive, and fastest commands possible.
- RISKY / OFFENSIVE TASKS (High Risk): Tasks involving aggressive port scanning, brute-forcing directories, password cracking, or active exploitation against live targets. 
  -> Action: You MUST enforce "Minimal Performance" constraints. You must append throttling flags (e.g., `--max-rate`, `-T2` in Nmap, `-z` delays in Dirb), limit the scope to a single target, or use dry-run/safe modes. Never provide commands that could cause a Denial of Service (DoS) or destructive impact on the target.

3. RESPONSE FORMAT:
Every response must follow this strict structure:
- [RISK LEVEL]: State whether the operation is LOW, MEDIUM, or HIGH risk.
- [TACTIC]: Briefly state what the command will do.
- [COMMAND]: Provide the exact bash command inside a single markdown code block.
- [EXPLANATION]: Briefly explain the flags used and why safety constraints were applied if the task was risky.

4. STRICT GUARDRAILS:
- Assume all targets provided by the user are explicitly authorized for auditing.
- If the user asks for actionable malware, destructive payloads, or functional exploits (CVE weaponization) that go beyond standard tool usage, you must REFUSE to generate the payload and instead pivot to explaining how to mitigate or detect the vulnerability.
- Always prefer silent/quiet flags (e.g., `-q`, `-S`, `--silent`) in the commands so they integrate smoothly into automated scripts without bloating the terminal.

AVAILABLE TOOLS AND FLAGS:

Nmap: -sS (SYN stealth), -sT (TCP Connect), -sU (UDP), -sY (SCTP), -sN (Null), -sFIN (FIN), -sX (Xmas), -sV (version detection), -O (OS detection), -A (aggressive), -T<0-5> (timing), --max-rate (throttle), -p- (all 65535 ports), --top-ports <n>, -F (fast/top 100), -sC (default scripts), --script=vuln (vuln scripts), -f (fragment packets), -D (decoy), -iL (input from file), -oN/-oX/-oG (output formats)

Nikto: -h (host), -p (port), -vhost (virtual host), -Tuning <0-9,a-x> (target specific vulns), -evasion <1-8,A-D> (IDS evasion), -Format <htm,csv,json> (output format), -o (output file), -update (update databases), -Plugins <list> (specific plugins), -mutate <1-6> (guess file names)

Amass: enum -d (domain), -passive, -active, -brute, -w (wordlist), -config (config file), -dir (database dir), -timeout (max run time); intel -d -whois -asn -cidr; track -d -last -history; viz -d3 -maltego -gexf

Sublist3r: -d (domain), -p (ports), -t (threads), -e (engines), -b (brute), -w (wordlist), -v (verbose), -o (output)

Gobuster: dir -u (url) -x (extensions) -c (cookies) -H (headers) -k (skip SSL); dns -d (domain) -r (resolver) -i (show IPs); vhost -u (url) --append-domain; s3 -w (wordlist). Global: -t (threads) -w (wordlist) -o (output) -q (quiet)

Dirb: <url> <wordlist>, -r (no recursion), -R (interactive recursion), -X (extensions), -x (extension file), -a (user-agent), -c (cookie), -z (delay ms), -u (user:pass), -p (proxy), -o (output), -S (silent), -w (ignore warnings), -N (ignore codes)

Hashcat: -a <0,1,3,6> (attack mode: 0=Dict, 1=Combo, 3=Mask, 6=Hybrid), -m <hash_id> (hash type: 0=MD5, 1000=NTLM, 1400=SHA256, 1800=sha512), -r (rules), ?l?u?d?s?a (mask characters), -O (optimized kernel), -w <1-4> (workload), -d (devices), --status, --status-json, --session, --restore, -o (output), --outfile-format, --show, --left

tcpdump: -i (interface), -i any (all interfaces), -w (write pcap), -r (read pcap), -n (no DNS), -nn (no DNS/port), -v/-vv/-vvv (verbosity), -X/-XX (hex dump), -A (ASCII), -c (count), -s (snaplen), BPF filters at end

Tshark: -i (interface), -r (read), -w (write), -c (count), -f (capture filter), -Y (display filter), -T fields -e (specific fields), -V (verbose tree), -O (protocol), -z (statistics), -q (quiet)

Snort: -v (sniffer), -d (dump payload), -e (MAC headers), -X (hex dump), -c (config), -T (test), -D (daemon), -Q (inline IPS), -i (interface), --daq (afpacket/nfq), -r (pcap), --pcap-dir (directory), -A (alert mode), -l (log dir), -q (quiet)

iptables: -A (append), -I (insert), -D (delete), -F (flush), -L (list), -s (source), -d (dest), -p (protocol), -i (input iface), -o (output iface), --sport (source port), --dport (dest port), -m state --state (connection state), -j ACCEPT/DROP/REJECT/LOG

nftables: nft add rule, nft list ruleset, nft flush ruleset

chkrootkit: -q (quiet), -x (expert), -r (root dir), -d (debug)

rkhunter: --check, --update, --report-warnings-only, --sk (skip keypress), --no-colors

ping: -c (count), -i (interval), -s (size), -W (timeout)
traceroute: -I (ICMP), -T (TCP), -p (port), -n (numeric), -m (max TTL), -w (timeout)
arp: -a (show cache), -d (delete), -s (static add)
whois: -H (hide legal), -p (port)

System: top, htop, df -h, free -h, ps aux, systemctl, journalctl, ss -tulnp, netstat -tulpn
"""


class SecOpsPrime:
    """Translates user security objectives into precise, risk-aware commands."""
    
    def __init__(self, ollama_host: str = "http://localhost:11434", model: str = "qwen3.5:4b"):
        self.ollama_host = ollama_host
        self.model = model
    
    def translate(self, user_input: str) -> Dict[str, str]:
        """
        Translate user's natural language into a structured security command.
        
        Returns dict with keys: risk_level, tactic, command, explanation, tool_name
        """
        if not self._is_available():
            return self._fallback_parse(user_input)
        
        try:
            response = self._call_ollama(user_input)
            if response:
                parsed = self._parse_response(response)
                if parsed.get("command"):
                    return parsed
        except Exception as e:
            pass
        
        return self._fallback_parse(user_input)
    
    def _is_available(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            req = urllib.request.Request(f"{self.ollama_host}/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False
    
    def _call_ollama(self, user_input: str) -> Optional[str]:
        """Send user input to Ollama with SecOps-Prime system prompt."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SECOPSPRIME_SYSTEM_PROMPT},
                {"role": "user", "content": user_input}
            ],
            "stream": False,
            "options": {
                "temperature": 0.3,
                "max_tokens": 800
            }
        }
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ollama_host}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=90) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("message", {}).get("content", "")
    
    def _parse_response(self, response: str) -> Dict[str, str]:
        """Parse the structured SecOps-Prime response."""
        result = {
            "risk_level": "MEDIUM",
            "tactic": "",
            "command": "",
            "explanation": "",
            "tool_name": ""
        }
        
        # Extract risk level
        risk_match = re.search(r'\[RISK LEVEL\]:\s*(LOW|MEDIUM|HIGH)', response, re.IGNORECASE)
        if risk_match:
            result["risk_level"] = risk_match.group(1).upper()
        
        # Extract tactic
        tactic_match = re.search(r'\[TACTIC\]:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
        if tactic_match:
            result["tactic"] = tactic_match.group(1).strip()
        
        # Extract command from code block
        cmd_match = re.search(r'```(?:bash)?\s*\n?(.+?)\n?```', response, re.DOTALL)
        if cmd_match:
            result["command"] = cmd_match.group(1).strip()
        
        # Extract explanation
        expl_match = re.search(r'\[EXPLANATION\]:\s*(.+?)(?:\n\n|\Z)', response, re.IGNORECASE | re.DOTALL)
        if expl_match:
            result["explanation"] = expl_match.group(1).strip()
        
        # Detect tool name from command
        if result["command"]:
            tool = result["command"].split()[0] if result["command"] else ""
            result["tool_name"] = tool
        
        return result
    
    def _fallback_parse(self, user_input: str) -> Dict[str, str]:
        """
        Comprehensive rule-based fallback when Ollama is unavailable.
        Handles ALL commands from the help text.
        """
        lower = user_input.lower().strip()
        result = {
            "risk_level": "MEDIUM",
            "tactic": "",
            "command": "",
            "explanation": "",
            "tool_name": ""
        }
        
        # Extract target/IP/domain
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,})', lower)
        target = ip_match.group(1) if ip_match else "127.0.0.1"
        
        # Extract hash (for hashcat)
        hash_match = re.search(r'([a-fA-F0-9]{32,128})', user_input)
        hash_val = hash_match.group(1) if hash_match else "5f4dcc3b5aa765d61d8327deb882cf99"
        
        # Extract interface
        iface_match = re.search(r'(eth\d+|wlan\d+|enp\w+|wlp\w+|lo)', lower)
        iface = iface_match.group(1) if iface_match else "any"
        
        # ===== BLUE TEAM (Automated Defense) =====
        
        # status - System status
        if any(w in lower for w in ["status", "system status", "system info"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "System Status Overview"
            result["command"] = "echo '=== SYSTEM STATUS ===' && echo '--- CPU ---' && top -bn1 | head -5 && echo '--- Memory ---' && free -h && echo '--- Disk ---' && df -h / && echo '--- Network ---' && ss -tulnp | head -10 && echo '--- Uptime ---' && uptime"
            result["tool_name"] = "system"
            result["explanation"] = "Comprehensive system status with CPU, memory, disk, network, and uptime."
        
        # detect threats / analyze attack
        elif any(w in lower for w in ["detect threat", "detect attacks", "analyze attack", "threat detection"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Threat Detection and Auto-Response"
            result["command"] = "echo '=== Threat Detection ===' && echo '--- Failed SSH ---' && grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 && echo '--- Suspicious IPs ---' && awk '/Failed password/{print $(NF-3)}' /var/log/auth.log 2>/dev/null | sort | uniq -c | sort -rn | head -10 && echo '--- Open Connections ---' && ss -tulnp | grep ESTAB"
            result["tool_name"] = "threat_detect"
            result["explanation"] = "Analyzes auth logs for brute-force attempts and lists suspicious connections."
        
        # show logs / siem
        elif any(w in lower for w in ["show logs", "siem", "log viewer", "view logs", "security logs"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "SIEM Log Viewer"
            result["command"] = "echo '=== SIEM Logs ===' && echo '--- Auth Log (last 20) ---' && tail -20 /var/log/auth.log 2>/dev/null && echo '--- Syslog (last 20) ---' && tail -20 /var/log/syslog 2>/dev/null && echo '--- Fail2Ban ---' && sudo fail2ban-client status 2>/dev/null && echo '--- Kernel ---' && dmesg | tail -10 2>/dev/null"
            result["tool_name"] = "siem"
            result["explanation"] = "Multi-source log viewer: auth, syslog, fail2ban, kernel."
        
        # block ip
        elif any(w in lower for w in ["block ip", "block traffic", "ban ip", "blacklist ip"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "IP Blocking via iptables"
            result["command"] = f"sudo iptables -A INPUT -s {target} -j DROP && echo 'IP {target} blocked. Verifying...' && sudo iptables -L INPUT -n | grep {target}"
            result["tool_name"] = "iptables"
            result["explanation"] = f"Blocks all inbound traffic from {target} using iptables DROP rule."
        
        # firewall check
        elif any(w in lower for w in ["firewall check", "firewall status", "fail2ban", "ufw"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Firewall Status Check"
            result["command"] = "echo '=== UFW Status ===' && sudo ufw status verbose 2>/dev/null && echo '=== Fail2Ban ===' && sudo fail2ban-client status 2>/dev/null && echo '=== iptables Rules ===' && sudo iptables -L -n --line-numbers | head -20"
            result["tool_name"] = "firewall"
            result["explanation"] = "Checks UFW, Fail2Ban, and iptables status."
        
        # rootkit scan
        elif any(w in lower for w in ["rootkit", "scan rootkit", "chkrootkit", "rkhunter"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Rootkit Detection Scan"
            result["command"] = "echo '=== rkhunter ===' && sudo rkhunter --check --sk --no-colors 2>/dev/null && echo '=== chkrootkit ===' && sudo chkrootkit -q 2>/dev/null"
            result["tool_name"] = "rkhunter"
            result["explanation"] = "Automated rootkit scan using rkhunter and chkrootkit."
        
        # ids monitor
        elif any(w in lower for w in ["ids monitor", "ids", "snort", "suricata", "intrusion detection"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "IDS Monitoring"
            result["command"] = "echo '=== Snort Status ===' && sudo snort -T -c /etc/snort/snort.conf 2>/dev/null && echo '=== Recent Alerts ===' && sudo tail -20 /var/log/snort/alert 2>/dev/null && echo '=== Network Stats ===' && sudo tcpdump -i any -c 10 -n 2>/dev/null"
            result["tool_name"] = "snort"
            result["explanation"] = "IDS monitoring: tests snort config, shows recent alerts, and captures sample traffic."
        
        # analyze anomaly
        elif any(w in lower for w in ["anomaly", "detect anomaly", "analyze anomaly", "anomaly detection"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "ML Anomaly Detection"
            result["command"] = "python3 -c \"from vrin_SOC.ml.anomaly_detector import AnomalyDetector; detector = AnomalyDetector(); result = detector.analyze(); print(result)\""
            result["tool_name"] = "anomaly_detector"
            result["explanation"] = "Runs ML-based anomaly detection on network/system telemetry."
        
        # risk score
        elif any(w in lower for w in ["risk score", "risk assessment", "calculate risk"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Risk Scoring Intelligence"
            result["command"] = "python3 -c \"from vrin_SOC.ml.risk_scoring import RiskScorer; scorer = RiskScorer(); result = scorer.calculate(); print(result)\""
            result["tool_name"] = "risk_scoring"
            result["explanation"] = "Calculates risk scores based on system vulnerabilities and threat intelligence."
        
        # ===== RED TEAM (Manual Approval Required) =====
        
        # scan network
        elif any(w in lower for w in ["scan network", "nmap scan", "network scan"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "Network Port Scan"
            result["command"] = f"sudo nmap -sV -sC -T3 {target} -oN network_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Standard service/version scan with default scripts and output to file."
        
        # whois
        elif any(w in lower for w in ["whois", "domain lookup", "domain info"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Domain WHOIS Lookup"
            result["command"] = f"whois {target} -H"
            result["tool_name"] = "whois"
            result["explanation"] = "Passive WHOIS lookup with legal disclaimer hidden."
        
        # scan vulnerabilities
        elif any(w in lower for w in ["scan vulnerabilities", "vulnerability scan", "vuln scan", "cve scan"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Throttled Vulnerability Scan"
            result["command"] = f"sudo nmap -sV --script=vuln --max-rate 100 -T2 {target} -oN vuln_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Aggressive NSE vulnerability scan throttled to prevent DoS. Rate limited to 100 pps."
        
        # nikto
        elif any(w in lower for w in ["nikto", "web scan", "web vulnerability"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "Web Server Vulnerability Scan"
            result["command"] = f"nikto -h {target} -Format json -o nikto_scan.json"
            result["tool_name"] = "nikto"
            result["explanation"] = "Web vulnerability scanner with JSON output for automation."
        
        # gobuster
        elif any(w in lower for w in ["gobuster", "directory brute force", "dir brute force"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Throttled Directory Brute-Force"
            result["command"] = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 10 -z 500 -o gobuster_results.txt"
            result["tool_name"] = "gobuster"
            result["explanation"] = "Directory brute-force with 500ms delay between requests and limited threads to avoid detection."
        
        # dirb
        elif any(w in lower for w in ["dirb", "dir scanner", "web directory"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Throttled Web Directory Scan"
            result["command"] = f"dirb {target} /usr/share/wordlists/dirb/common.txt -z 500 -S -o dirb_results.txt"
            result["tool_name"] = "dirb"
            result["explanation"] = "Web directory scanner with 500ms delay and silent mode for automation."
        
        # amass
        elif any(w in lower for w in ["amass", "subdomain enum", "enumerate subdomain", "passive recon"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Passive Subdomain Enumeration"
            result["command"] = f"amass enum -d {target} -passive -o amass_subdomains.txt"
            result["tool_name"] = "amass"
            result["explanation"] = "Passive enumeration only - no direct queries to target. Safe for reconnaissance."
        
        # sublist3r
        elif any(w in lower for w in ["sublist3r", "fast subdomain", "quick subdomain"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Multi-Engine Subdomain Brute-Force"
            result["command"] = f"python3 sublist3r.py -d {target} -t 10 -o sublist3r_subdomains.txt"
            result["tool_name"] = "sublist3r"
            result["explanation"] = "Multi-engine subdomain enumeration with 10 threads."
        
        # tcpdump
        elif any(w in lower for w in ["tcpdump", "packet capture", "capture packets", "sniff traffic"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Limited Packet Capture"
            result["command"] = f"sudo tcpdump -i {iface} -c 50 -w capture.pcap -n && echo 'Captured 50 packets to capture.pcap'"
            result["tool_name"] = "tcpdump"
            result["explanation"] = "Limited capture of 50 packets to prevent disk overflow. No DNS resolution."
        
        # wireshark / tshark
        elif any(w in lower for w in ["wireshark", "tshark", "protocol analysis", "deep packet"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Deep Protocol Analysis"
            result["command"] = f"sudo tshark -i {iface} -c 100 -Y 'http || dns || tls' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null"
            result["tool_name"] = "tshark"
            result["explanation"] = "Deep protocol analysis with display filters for HTTP/DNS/TLS."
        
        # hashcat
        elif any(w in lower for w in ["hashcat", "crack hash", "password crack", "hash crack"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Hashcat Password Cracking (Suggestion Only)"
            result["command"] = f"# Dictionary attack on {hash_val}\nhashcat -a 0 -m 0 {hash_val} /usr/share/wordlists/rockyou.txt --status --session crack_session -o cracked.txt\n# Show results\nhashcat --show -m 0 {hash_val} --outfile-format 2"
            result["tool_name"] = "hashcat"
            result["explanation"] = "Hashcat dictionary attack suggestion. Requires GPU and explicit user approval to run."
        
        # os detection
        elif any(w in lower for w in ["os detect", "os fingerprint", "operating system detect"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "OS Fingerprinting"
            result["command"] = f"sudo nmap -O --osscan-guess -T2 {target} -oN os_detect.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "OS detection with throttled timing to reduce network impact."
        
        # ===== INTELLIGENCE =====
        
        # anomaly detection (ML)
        elif any(w in lower for w in ["anomaly detection", "ml anomaly", "isolationforest"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "ML Anomaly Detection"
            result["command"] = "python3 -c \"from vrin_SOC.ml.anomaly_detector import AnomalyDetector; detector = AnomalyDetector(); result = detector.score(); print(result)\""
            result["tool_name"] = "anomaly_detector"
            result["explanation"] = "IsolationForest anomaly scoring on network/system data."
        
        # dashboard
        elif any(w in lower for w in ["dashboard", "soc dashboard", "web dashboard"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "SOC Dashboard"
            result["command"] = "python3 vrin_SOC/api/main.py &"
            result["tool_name"] = "dashboard"
            result["explanation"] = "Starts the SOC web dashboard."
        
        # ===== HIVE (Agent Coordination) =====
        
        # hive status
        elif any(w in lower for w in ["hive status", "hive health", "agent status"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Hive Health Overview"
            result["command"] = "python3 -c \"from vrin_SOC.hive.coordinator import hive; import json; print(json.dumps(hive.get_status(), indent=2))\""
            result["tool_name"] = "hive"
            result["explanation"] = "Shows hive health, connected agents, and task queue status."
        
        # hive agents
        elif any(w in lower for w in ["hive agents", "list agents", "registered agents"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "List Registered Agents"
            result["command"] = "python3 -c \"from vrin_SOC.hive.coordinator import hive; import json; print(json.dumps(hive.get_agents(), indent=2))\""
            result["tool_name"] = "hive"
            result["explanation"] = "Lists all registered agents with their status and capabilities."
        
        # hive snapshot
        elif any(w in lower for w in ["hive snapshot", "point in time snapshot", "hive state"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Hive Point-in-Time Snapshot"
            result["command"] = "python3 -c \"from vrin_SOC.hive.coordinator import hive; import json; print(json.dumps(hive.get_snapshot(), indent=2))\""
            result["tool_name"] = "hive"
            result["explanation"] = "Full hive point-in-time snapshot including all agent states."
        
        # hive tasks
        elif any(w in lower for w in ["hive tasks", "task queue", "pending tasks"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Hive Task Queue"
            result["command"] = "python3 -c \"from vrin_SOC.hive.coordinator import hive; import json; print(json.dumps(hive.get_tasks(), indent=2))\""
            result["tool_name"] = "hive"
            result["explanation"] = "Shows hive task queue with pending, running, and completed tasks."
        
        # reap stale agents
        elif any(w in lower for w in ["reap stale", "stale agents", "offline agents", "cleanup agents"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Mark Offline Agents"
            result["command"] = "python3 -c \"from vrin_SOC.hive.coordinator import hive; result = hive.reap_stale_agents(); print(f'Marked {result} stale agents as offline')\""
            result["tool_name"] = "hive"
            result["explanation"] = "Marks offline/stale agents as inactive."
        
        # ===== GENERAL RECONNAISSANCE =====
        
        # ping sweep
        elif any(w in lower for w in ["ping sweep", "host discovery", "network discovery"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Host Discovery"
            result["command"] = f"sudo nmap -sn {target}/24 -oN host_discovery.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Ping sweep for host discovery (no port scan)."
        
        # full port scan
        elif any(w in lower for w in ["full port scan", "all ports", "port scan all"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Full Port Scan (All 65535)"
            result["command"] = f"sudo nmap -p- --max-rate 200 -T2 {target} -oN full_ports.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Full 65535 port scan with throttled rate to avoid detection."
        
        # dns enumeration
        elif any(w in lower for w in ["dns enum", "dns lookup", "dns records"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "DNS Enumeration"
            result["command"] = f"dig +short {target} ANY 2>/dev/null && echo '---' && dig +short ns {target} 2>/dev/null && echo '---' && dig +short mx {target} 2>/dev/null"
            result["tool_name"] = "dig"
            result["explanation"] = "DNS enumeration: ANY, NS, and MX records."
        
        # ssl scan
        elif any(w in lower for w in ["ssl scan", "ssl cert", "tls scan", "certificate"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "SSL/TLS Certificate Scan"
            result["command"] = f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null"
            result["tool_name"] = "openssl"
            result["explanation"] = "SSL/TLS certificate inspection."
        
        # mail server scan
        elif any(w in lower for w in ["mail scan", "smtp", "email server"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Mail Server Scan"
            result["command"] = f"sudo nmap -p 25,465,587,993,995 -sV --script=smtp-commands,smtp-open-relay {target} -oN mail_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Mail server scan with SMTP enumeration and open relay detection."
        
        # database scan
        elif any(w in lower for w in ["database scan", "db scan", "mysql", "postgres", "mongodb"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "Database Service Scan"
            result["command"] = f"sudo nmap -p 3306,5432,27017,1433,6379 -sV --script=mysql-info,postgres-info,mongo-databases {target} -oN db_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Database service scan with enumeration scripts."
        
        # Default fallback
        else:
            result["risk_level"] = "LOW"
            result["tactic"] = "General Reconnaissance"
            result["command"] = f"sudo nmap -sV -sC -T3 {target} -oN recon.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Default reconnaissance scan with service detection."
        
        return result


# Global instance
secops_prime = SecOpsPrime()
