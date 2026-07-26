"""
Vrindha Core Brain (Orchestrator) - MASTER BLUEPRINT
Responsibilities: Interpret user commands, route tasks to agents, handle responses, maintain modular architecture
System Modes: DEFENSIVE MODE (default), RED TEAM MODE (manual approval required)
CORE RULES: NEVER execute offensive without approval, AUTOMATE defensive when threat, ALWAYS validate permissions, LOG every action, HANDLE errors gracefully
WORKFLOW: Receive command -> Classify Red/Blue -> Red->Ask->Execute manual, Blue->Detect->Auto Respond -> Log Everything
OUTPUT FORMAT: {mode, action, status, message, data}
"""
import re
from datetime import datetime
from typing import Dict, Any
import sys
from pathlib import Path

# Ensure imports work when run from different locations
sys.path.append(str(Path(__file__).parent.parent))

from core.intent_analyzer import intent_analyzer
from core.dharma_engine import dharma_engine
from core.authorization import authorization_layer
from core.safety_layer import safety_layer
from core.gita_engine import gita_engine
from core.tool_executor import tool_executor
from core.iam_module import iam_module
from core.zero_trust_engine import zero_trust_engine
from core.memory_system import memory_system
from core.planning_engine import planning_engine
from core.knowledge_base import knowledge_base
from core.error_handler import ErrorHandler

# Agents will be imported lazily to avoid circular imports
class Brain:
    """
    Central AI orchestrator - Vrindha
    """
    
    def __init__(self):
        self.mode = "defensive"  # default per blueprint
        self.pending_confirmations = {}  # store commands awaiting confirmation
        self.last_command_id = 0
        print("[Brain] Vrindha AI SOC System initialized in DEFENSIVE MODE")
    
    def classify_command(self, command: str) -> Dict:
        """Classify as red/blue per blueprint"""
        cmd_lower = command.lower()
        
        red_keywords = ["scan", "nmap", "recon", "vulnerability", "nikto", "gobuster", "dirb", "amass", "sublist3r", "whois", "wireshark", "tcpdump", "metasploit", "hashcat", "hydra", "burpsuite", "exploit", "penetration"]
        blue_keywords = ["threat", "detect", "block", "protect", "defense", "monitor", "siem", "log", "alert", "status", "firewall", "endpoint", "rootkit", "anomaly", "risk"]
        
        red_score = sum(1 for kw in red_keywords if kw in cmd_lower)
        blue_score = sum(1 for kw in blue_keywords if kw in cmd_lower)
        
        # Also check explicit
        if any(x in cmd_lower for x in ["hello", "hi", "help", "status", "dashboard", "logs"]):
            return {"mode": "blue", "type": "general", "confidence": "high"}
        
        if red_score > blue_score:
            return {"mode": "red", "type": "offensive", "confidence": "medium", "red_score": red_score, "blue_score": blue_score}
        elif blue_score > 0:
            return {"mode": "blue", "type": "defensive", "confidence": "medium", "red_score": red_score, "blue_score": blue_score}
        else:
            # Default to general/blue for safety
            return {"mode": "blue", "type": "general", "confidence": "low"}
    
    def extract_target(self, command: str) -> str:
        """Extract target IP/domain from command"""
        # IP regex
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        match = re.search(ip_pattern, command)
        if match:
            return match.group(0)
        # Domain regex after keywords
        domain_pattern = r"(?:scan|whois|nmap|gobuster|dirb|amass|sublist3r)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        m = re.search(domain_pattern, command, re.IGNORECASE)
        if m:
            return m.group(1)
        # Simple token after keywords
        tokens = command.split()
        for i, tok in enumerate(tokens):
            if tok.lower() in ["scan", "whois", "nmap", "target", "on", "for"] and i+1 < len(tokens):
                candidate = tokens[i+1]
                if "." in candidate or candidate == "localhost" or candidate == "127.0.0.1":
                    return candidate
        return ""
    
    def process(self, command: str, auto_confirm: bool = False, user_token: str = None) -> Dict[str, Any]:
        """
        Main process method per blueprint
        Handles pending confirmation flow
        """
        try:
            command = command.strip()
            if not command:
                return {"mode": "blue", "action": "empty", "status": "error", "message": "Empty command", "data": {}}
            
            # Check if this is a confirmation response to previous command
            if command.lower() in ["yes", "y", "confirm", "proceed"] and self.pending_confirmations:
                # Get last pending
                last_id = max(self.pending_confirmations.keys())
                pending = self.pending_confirmations.pop(last_id)
                return self._execute_confirmed(pending["original_command"], pending)
            
            if command.lower() in ["no", "n", "cancel", "abort"] and self.pending_confirmations:
                last_id = max(self.pending_confirmations.keys())
                self.pending_confirmations.pop(last_id)
                return {"mode": "red", "action": "cancelled", "status": "success", "message": "Action cancelled by user per Red Team safety", "data": {}}
            
            # Handle basic commands per 30-day plan
            if command.lower() in ["hello", "hi"]:
                verse = gita_engine.get_random_verse()
                return {
                    "mode": "blue",
                    "action": "greeting",
                    "status": "success",
                    "message": f"Hello! I am Vrindha, your AI-powered SOC assistant. Running in DEFENSIVE MODE. {verse.get('meaning','Performing duty with protection.')}",
                    "data": {"gita_verse": verse}
                }
            
            if command.lower() == "status":
                stats = memory_system.get_stats()
                return {
                    "mode": "blue",
                    "action": "status",
                    "status": "success",
                    "message": "System running - Vrindha AI SOC",
                    "data": {
                        "mode": self.mode,
                        "brain": "active",
                        "agents": ["ReconAgent", "VulnAgent", "ThreatAgent", "SIEMAgent"],
                        "tools": ["nmap", "whois", "nikto", "amass", "gobuster", "fail2ban", "rkhunter"],
                        "memory": stats,
                        "gita_status": "loaded" if gita_engine.loaded else "not loaded"
                    }
                }
            
            if "help" in command.lower():
                return {
                    "mode": "blue",
                    "action": "help",
                    "status": "success",
                    "message": self.get_help_text(),
                    "data": {}
                }
            
            # Zero Trust check first
            zt_result = zero_trust_engine.evaluate_command(command)
            if zt_result.get("access_decision") == "deny" and zt_result.get("trust_score", 100) < 20:
                return {
                    "mode": "blue",
                    "action": "blocked_by_zero_trust",
                    "status": "denied",
                    "message": f"Zero Trust Engine denied command. Trust score: {zt_result.get('trust_score')}. Alerts: {zt_result.get('alerts')}",
                    "data": zt_result
                }
            
            # Classify
            classification = self.classify_command(command)
            mode = classification["mode"]
            target = self.extract_target(command)
            
            # Safety Layer evaluation
            safety = safety_layer.evaluate_request(command, target, mode=mode)
            
            # Memory: retrieve similar cases
            similar_cases = memory_system.retrieve_similar(command)
            
            # Planning engine suggestions
            plan = planning_engine.plan(command)
            
            # Route based on mode
            if mode == "red":
                return self._handle_red_team(command, target, classification, safety, similar_cases, plan, auto_confirm, user_token)
            else:
                return self._handle_blue_team(command, target, classification, safety, similar_cases, plan)
                
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain.process")
            return {
                "mode": "unknown",
                "action": "error",
                "status": "error",
                "message": f"Brain error: {e}",
                "data": err,
                "gita_guidance": gita_engine.get_ethical_guidance("defense")
            }
    
    def _handle_red_team(self, command: str, target: str, classification: Dict, safety: Dict, similar: Dict, plan: Dict, auto_confirm: bool, user_token) -> Dict:
        """Red Team → Manual Only per blueprint"""
        # Dharma check already in safety
        dharma = safety.get("dharma", {})
        
        if safety.get("decision") == "deny":
            return {
                "mode": "red",
                "action": "denied",
                "status": "denied",
                "message": f"⛔ DENIED: {safety.get('reason')}. True strength lies in protecting, not exploiting. (Dharma Engine)",
                "data": {
                    "dharma": dharma,
                    "safety": safety,
                    "gita_verse": dharma.get("gita_verse"),
                    "educational": dharma.get("educational", "Use your skills to protect, not harm.")
                }
            }
        
        # If requires confirmation (always for red team per blueprint)
        if safety.get("requires_confirmation") or not auto_confirm:
            self.last_command_id += 1
            self.pending_confirmations[self.last_command_id] = {
                "original_command": command,
                "target": target,
                "classification": classification,
                "safety": safety,
                "timestamp": datetime.now().isoformat()
            }
            
            # Build what will happen explanation
            preview = self._build_red_preview(command, target)
            
            return {
                "mode": "red",
                "action": "confirmation_required",
                "status": "awaiting_confirmation",
                "message": f"🔴 RED TEAM MODE - Manual Approval Required per Safety Blueprint\n\nI will: {preview}\nTarget: {target or 'not specified, will use 127.0.0.1 for safety'}\nSafety: {safety.get('reason')}\nRisk: {dharma.get('risk_level','medium')}\n\nDo you want to proceed? (yes/no)",
                "data": {
                    "pending_id": self.last_command_id,
                    "preview": preview,
                    "target": target,
                    "safety": safety,
                    "dharma": dharma,
                    "similar_cases": similar,
                    "plan": plan,
                    "gita_verse": dharma.get("gita_verse")
                }
            }
        else:
            # Auto-confirmed (via auto_confirm flag) - execute
            return self._execute_confirmed(command, {"target": target, "classification": classification, "safety": safety})
    
    def _build_red_preview(self, command: str, target: str) -> str:
        cmd_lower = command.lower()
        if "nmap" in cmd_lower or "scan network" in cmd_lower:
            return f"Run nmap -sV on {target or '127.0.0.1'} to discover open ports and services"
        if "whois" in cmd_lower:
            return f"Run whois lookup on {target or 'example.com'}"
        if "vuln" in cmd_lower or "nikto" in cmd_lower:
            return f"Run vulnerability scan (nikto) on {target or '127.0.0.1'}"
        if "gobuster" in cmd_lower:
            return f"Run Gobuster directory brute force on {target}"
        if "amass" in cmd_lower:
            return f"Run Amass sub-domain enumeration on {target}"
        if "sublist3r" in cmd_lower:
            return f"Run Sublist3r on {target}"
        if "tcpdump" in cmd_lower:
            return f"Run tcpdump capture (limited to 50 packets) on interface {target or 'eth0'}"
        if "hashcat" in cmd_lower:
            return "Suggest hashcat command (no auto-run) and explain risks per strict control"
        return f"Execute recon action for command '{command}' with safety timeout"
    
    def _execute_confirmed(self, command: str, context: Dict) -> Dict:
        """Execute after user confirmation"""
        try:
            target = context.get("target") or self.extract_target(command) or "127.0.0.1"
            cmd_lower = command.lower()
            
            # Lazy imports to avoid circular
            from agents.recon_agent import recon_agent
            from agents.vuln_agent import vuln_agent
            from agents.threat_agent import threat_agent
            from agents.siem_agent import siem_agent
            
            result_data = {}
            message = ""
            
            # Route to appropriate agent per 30-day and startup blueprints
            if "scan network" in cmd_lower or "nmap" in cmd_lower:
                result_data = recon_agent.run(target)
                message = f"Nmap scan completed on {target}"
            elif "whois" in cmd_lower:
                from tools.whois_tool import run_whois
                result_data = run_whois(target if target else "google.com")
                message = f"Whois lookup for {target}"
            elif "vulnerab" in cmd_lower or "nikto" in cmd_lower:
                result_data = vuln_agent.run(target)
                message = f"Vulnerability scan on {target}"
            elif "gobuster" in cmd_lower:
                from tools.gobuster_tool import run_gobuster
                result_data = run_gobuster(target)
                message = f"Gobuster scan on {target}"
            elif "dirb" in cmd_lower:
                from tools.dirb_tool import run_dirb
                result_data = run_dirb(target)
                message = f"Dirb scan on {target}"
            elif "amass" in cmd_lower:
                from tools.amass_tool import run_amass
                result_data = run_amass(target)
                message = f"Amass enum on {target}"
            elif "sublist3r" in cmd_lower:
                from tools.sublist3r_tool import run_sublist3r
                result_data = run_sublist3r(target)
                message = f"Sublist3r on {target}"
            elif "tcpdump" in cmd_lower:
                from tools.tcpdump_tool import run_tcpdump
                result_data = run_tcpdump(target or "eth0")
                message = f"tcpdump on {target}"
            elif "hashcat" in cmd_lower:
                from tools.hashcat_tool import run_hashcat_assistant
                result_data = run_hashcat_assistant(command)
                message = "Hashcat assistant - command suggested, not auto-executed per strict control"
            else:
                # Generic recon
                result_data = recon_agent.run(target)
                message = f"Recon scan on {target}"
            
            # Memory save
            memory_system.save_memory({
                "event_type": "red_team_scan",
                "threat": f"recon {target}",
                "action_taken": command,
                "outcome": str(result_data)[:500],
                "risk_level": "Medium",
                "timestamp": datetime.now().isoformat()
            })
            
            # Log to SIEM
            try:
                from database.db import add_log
                add_log(command, str(result_data)[:2000], "Medium")
            except:
                pass
            
            # Threat analysis on result
            threat_analysis = threat_agent.analyze(str(result_data))
            
            return {
                "mode": "red",
                "action": "executed",
                "status": "success",
                "message": message + f" | Threat Level: {threat_analysis.get('threat_level','Low')}",
                "data": {
                    "result": result_data,
                    "threat_analysis": threat_analysis,
                    "target": target,
                    "gita_guidance": gita_engine.get_ethical_guidance("defense")
                }
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain._execute_confirmed")
            return {
                "mode": "red",
                "action": "execution_failed",
                "status": "error",
                "message": f"Execution failed after confirmation: {e}",
                "data": err
            }
    
    def _handle_blue_team(self, command: str, target: str, classification: Dict, safety: Dict, similar: Dict, plan: Dict) -> Dict:
        """Blue Team → CAN be automated per blueprint"""
        try:
            from agents.threat_agent import threat_agent
            from agents.siem_agent import siem_agent
            from automation.actions import automation_actions
            
            cmd_lower = command.lower()
            
            # Threat detection
            if any(k in cmd_lower for k in ["threat", "attack", "breach", "malware"]):
                # Analyze text for threat levels per Day 17
                threat_result = threat_agent.analyze(command)
                
                # Automated response if HIGH risk per Day 22-23
                automated_action = None
                if threat_result.get("risk_level") == "HIGH" or threat_result.get("threat_level") == "HIGH":
                    automated_action = automation_actions.block_ip("192.168.1.100")  # example suspicious
                    # Memory
                    memory_system.save_memory({
                        "event_type": "auto_response",
                        "threat": command,
                        "action_taken": "block_ip",
                        "outcome": str(automated_action),
                        "risk_level": "HIGH"
                    })
                
                return {
                    "mode": "blue",
                    "action": "threat_detection",
                    "status": "success",
                    "message": f"Threat analysis completed - Level: {threat_result.get('threat_level')} | Automated: {automated_action is not None}",
                    "data": {
                        "threat": threat_result,
                        "automated_action": automated_action,
                        "safety": safety,
                        "similar": similar,
                        "gita_guidance": gita_engine.get_ethical_guidance("defense")
                    }
                }
            
            if "log" in cmd_lower or "siem" in cmd_lower:
                logs = siem_agent.get_logs()
                return {
                    "mode": "blue",
                    "action": "siem_logs",
                    "status": "success",
                    "message": f"Retrieved {len(logs.get('logs',[])) if isinstance(logs, dict) else 'logs'} from SIEM",
                    "data": logs
                }
            
            if "block ip" in cmd_lower:
                ip_to_block = target or "192.168.1.100"
                result = automation_actions.block_ip(ip_to_block)
                return {
                    "mode": "blue",
                    "action": "block_ip",
                    "status": "success",
                    "message": f"Automated defensive action: Blocked IP {ip_to_block}",
                    "data": result
                }
            
            if "firewall" in cmd_lower or "fail2ban" in cmd_lower:
                from automation.firewall import firewall_module
                result = firewall_module.check_and_block()
                return {
                    "mode": "blue",
                    "action": "firewall_check",
                    "status": "success",
                    "message": "Firewall auto-response check completed",
                    "data": result
                }
            
            if "rootkit" in cmd_lower or "rkhunter" in cmd_lower or "chkrootkit" in cmd_lower:
                from automation.rootkit_scanner import rootkit_scanner
                result = rootkit_scanner.scan()
                return {
                    "mode": "blue",
                    "action": "rootkit_scan",
                    "status": "success",
                    "message": "Endpoint rootkit scan completed",
                    "data": result
                }
            
            if "ids" in cmd_lower or "snort" in cmd_lower or "suricata" in cmd_lower:
                from automation.ids_monitor import ids_monitor
                result = ids_monitor.monitor()
                return {
                    "mode": "blue",
                    "action": "ids_monitor",
                    "status": "success",
                    "message": "IDS monitoring completed - Blue Team automated",
                    "data": result
                }
            
            if "anomaly" in cmd_lower or "risk" in cmd_lower:
                from ml.anomaly_detector import anomaly_detector
                from ml.risk_scoring import risk_scoring
                # Simulate log analysis
                anomaly = anomaly_detector.detect({"command": command})
                risk = risk_scoring.score({"ip": target or "127.0.0.1", "events": [command]})
                return {
                    "mode": "blue",
                    "action": "intelligence",
                    "status": "success",
                    "message": f"Anomaly score: {anomaly.get('anomaly_score')} | Risk: {risk.get('risk_score')}",
                    "data": {"anomaly": anomaly, "risk": risk}
                }
            
            # IAM check
            if "login" in cmd_lower or "auth" in cmd_lower or "brute force" in cmd_lower:
                iam_result = iam_module.analyze_logs(command)
                return {
                    "mode": "blue",
                    "action": "iam_analysis",
                    "status": "success",
                    "message": "IAM analysis completed",
                    "data": iam_result
                }
            
            # Default blue response
            return {
                "mode": "blue",
                "action": "general",
                "status": "success",
                "message": f"Blue Team automated response: Processed '{command}' with defensive posture. Use 'help' for commands.",
                "data": {
                    "classification": classification,
                    "safety": safety,
                    "plan": plan,
                    "similar_cases": similar,
                    "gita_verse": gita_engine.get_random_verse()
                }
            }
            
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain._handle_blue_team")
            return {
                "mode": "blue",
                "action": "error",
                "status": "error",
                "message": f"Blue team handling error: {e}",
                "data": err
            }
    
    def get_help_text(self) -> str:
        return """
Vrindha AI SOC - Help

🔵 BLUE TEAM (Automated Defense):
- status - System status
- detect threats / analyze attack - Threat detection with auto-response
- show logs / siem - SIEM log viewer
- block ip <ip> - Block suspicious IP
- firewall check - Fail2Ban/UFW auto response
- rootkit scan - rkhunter/chkrootkit
- ids monitor - Snort/Suricata monitoring
- analyze anomaly - ML anomaly detection
- risk score - Risk scoring intelligence

🔴 RED TEAM (Manual Approval Required):
- scan network <target> - Nmap recon (needs yes/no)
- whois <domain> - Whois lookup
- scan vulnerabilities <target> - Nikto vuln scan
- gobuster <url> - Directory brute force
- dirb <url> - Dirb scan
- amass <domain> - Subdomain enumeration
- sublist3r <domain> - Sublist3r
- tcpdump <interface> - Packet capture (50 packets limited)
- hashcat <hash> - Hashcat assistant (suggestion only)

🧠 INTELLIGENCE:
- anomaly detection - IsolationForest anomaly scoring
- dashboard - Open SOC dashboard (web)

🕉️ DHARMA ENGINE:
All actions evaluated for ethical compliance per Bhagavad Gita.
Red Team requires explicit "yes" confirmation.
"""

# Global brain instance
brain = Brain()
