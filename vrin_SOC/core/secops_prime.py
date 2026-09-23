"""
SecOps-Prime: Autonomous Security Emulation Agent
Translates user security objectives into precise, pipeline-ready commands
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
- Whenever the user asks to perform an action (e.g., "scan this network", "block this IP", "find subdomains"), you must provide the exact, syntactically perfect Linux terminal command(s) required to achieve the goal.
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
- [TACTIC]: Briefly state what the command will do (e.g., "Passive Subdomain Enumeration" or "Throttled Directory Brute-Force").
- [COMMAND]: Provide the exact bash command inside a single markdown code block.
- [EXPLANATION]: Briefly explain the flags used and why safety constraints were applied if the task was risky.

4. STRICT GUARDRAILS:
- Assume all targets provided by the user are explicitly authorized for auditing.
- If the user asks for actionable malware, destructive payloads, or functional exploits (CVE weaponization) that go beyond standard tool usage, you must REFUSE to generate the payload and instead pivot to explaining how to mitigate or detect the vulnerability.
- Always prefer silent/quiet flags (e.g., `-q`, `-S`, `--silent`) in the commands so they integrate smoothly into automated scripts without bloating the terminal.

AVAILABLE TOOLS:
- nmap: Port scanning, service detection, OS fingerprinting, NSE scripts, IPv6
- nikto: Web server vulnerability scanner
- amass: Subdomain enumeration, asset discovery
- sublist3r: Fast subdomain brute-forcing
- gobuster: Directory/file brute-forcing, DNS, vhost, S3
- dirb: Web directory scanner
- hashcat: Password cracking, hash brute-forcing
- tcpdump: Packet capture and analysis
- tshark (wireshark): Deep protocol analysis
- snort: Intrusion detection/prevention
- iptables/nftables: Firewall rule management
- chkrootkit: Rootkit detection
- rkhunter: Rootkit detection
- ping, traceroute, arp, whois: Network basics

TOOL FLAGS REFERENCE:
Nmap: -sS (SYN), -sT (TCP Connect), -sU (UDP), -sV (version), -O (OS), -A (aggressive), -T<0-5> (timing), --max-rate (throttle), -p- (all ports), --top-ports, -sC (default scripts), --script=vuln, -f (fragment), -D (decoy)
Nikto: -h (host), -p (port), -Tuning (target vulns), -evasion (IDS evasion), -Format (output), -o (output file)
Amass: enum -d (domain), -passive, -active, -brute; intel -d -whois; track -d
Sublist3r: -d (domain), -p (ports), -t (threads), -e (engines), -b (brute), -o (output)
Gobuster: dir -u (url) -x (ext) -c (cookies); dns -d (domain); vhost -u (url)
Dirb: <url> <wordlist>, -X (ext), -z (delay), -u (auth), -o (output), -S (silent)
Hashcat: -a (mode), -m (hash type), -r (rules), -O (optimized), -w (workload), --status, -o (output)
tcpdump: -i (interface), -w (write), -r (read), -n (no DNS), -c (count), -s (snaplen)
Tshark: -i (interface), -r (read), -Y (display filter), -T fields -e (fields), -z (stats)
Snort: -c (config), -T (test), -D (daemon), -Q (inline IPS), -A (alert mode)
iptables: -A (append), -I (insert), -D (delete), -F (flush), -s (source), -d (dest), -p (protocol), --dport (dest port), -j ACCEPT/DROP/REJECT/LOG
chkrootkit: -q (quiet), -x (expert), -r (root dir)
rkhunter: --check, --update, --report-warnings-only, --sk
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
        """Rule-based fallback when Ollama is unavailable."""
        lower = user_input.lower().strip()
        result = {
            "risk_level": "MEDIUM",
            "tactic": "",
            "command": "",
            "explanation": "",
            "tool_name": ""
        }
        
        # Extract target/IP
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,})', lower)
        target = ip_match.group(1) if ip_match else "127.0.0.1"
        
        # Map common phrases to commands
        if any(w in lower for w in ["vuln", "vulnerability", "cve", "exploit"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Throttled Vulnerability Scan"
            result["command"] = f"sudo nmap -sV --script=vuln --max-rate 100 -T2 {target} -oN vuln_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Aggressive scan throttled to prevent DoS. Uses NSE vuln scripts."
        
        elif any(w in lower for w in ["port", "open port", "scan port"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "Port Scan"
            result["command"] = f"sudo nmap -sV -sC -T3 {target} -oN port_scan.txt"
            result["tool_name"] = "nmap"
            result["explanation"] = "Standard service/version scan with default scripts."
        
        elif any(w in lower for w in ["subdomain", "subdomains", "enumerate subdomain"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Passive Subdomain Enumeration"
            result["command"] = f"amass enum -d {target} -passive -o subdomains.txt"
            result["tool_name"] = "amass"
            result["explanation"] = "Passive enumeration only - no direct queries to target."
        
        elif any(w in lower for w in ["directory", "dir", "brute force", "web directory"]):
            result["risk_level"] = "HIGH"
            result["tactic"] = "Throttled Directory Brute-Force"
            result["command"] = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 10 -z 500 -o dir_results.txt"
            result["tool_name"] = "gobuster"
            result["explanation"] = "Throttled with delays to avoid overwhelming the server."
        
        elif any(w in lower for w in ["firewall", "block ip", "iptables"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Firewall Rule"
            result["command"] = f"sudo iptables -A INPUT -s {target} -j DROP"
            result["tool_name"] = "iptables"
            result["explanation"] = "Standard defensive firewall rule to block source IP."
        
        elif any(w in lower for w in ["packet", "capture", "sniff"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Packet Capture"
            result["command"] = f"sudo tcpdump -i any -c 100 -w capture.pcap"
            result["tool_name"] = "tcpdump"
            result["explanation"] = "Limited capture of 100 packets to file."
        
        elif any(w in lower for w in ["rootkit", "scan rootkit"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Rootkit Detection"
            result["command"] = "sudo rkhunter --check --sk"
            result["tool_name"] = "rkhunter"
            result["explanation"] = "Automated rootkit scan with --sk for non-interactive mode."
        
        elif any(w in lower for w in ["nikto", "web scan"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "Web Server Vulnerability Scan"
            result["command"] = f"nikto -h {target} -Format json -o nikto_scan.json"
            result["tool_name"] = "nikto"
            result["explanation"] = "Web scanner with JSON output for automation."
        
        elif any(w in lower for w in ["os", "os detect", "operating system"]):
            result["risk_level"] = "MEDIUM"
            result["tactic"] = "OS Fingerprinting"
            result["command"] = f"sudo nmap -O --osscan-guess -T2 {target}"
            result["tool_name"] = "nmap"
            result["explanation"] = "OS detection with throttled timing."
        
        elif any(w in lower for w in ["whois", "domain info"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Domain Registration Lookup"
            result["command"] = f"whois {target}"
            result["tool_name"] = "whois"
            result["explanation"] = "Passive WHOIS lookup."
        
        elif any(w in lower for w in ["sublist3r", "fast subdomain"]):
            result["risk_level"] = "LOW"
            result["tactic"] = "Fast Subdomain Brute-Force"
            result["command"] = f"python3 sublist3r.py -d {target} -t 10 -o subdomains.txt"
            result["tool_name"] = "sublist3r"
            result["explanation"] = "Multi-engine subdomain enumeration."
        
        else:
            result["risk_level"] = "LOW"
            result["tactic"] = "General Reconnaissance"
            result["command"] = f"sudo nmap -sV -sC -T3 {target}"
            result["tool_name"] = "nmap"
            result["explanation"] = "Default reconnaissance scan."
        
        return result


# Global instance
secops_prime = SecOpsPrime()
