"""
Vrindha Core Brain (Orchestrator) - MASTER BLUEPRINT
Responsibilities: Interpret user commands, route tasks to agents, handle responses, maintain modular architecture
System Modes: DEFENSIVE MODE (default), RED TEAM MODE (manual approval required)
CORE RULES: NEVER execute offensive without approval, AUTOMATE low-impact defensive analysis/alerts, REQUIRE human validation for high-impact containment, ALWAYS validate permissions, LOG every action, HANDLE errors gracefully
WORKFLOW: Receive command -> Classify Red/Blue -> Red->Ask->Execute manual, Blue->Detect->Risk Score->Human-validated Response -> Log Everything
OUTPUT FORMAT: {mode, action, status, message, data}
"""
import re
from datetime import datetime
from typing import Dict, Any

from .intent_analyzer import intent_analyzer
from .dharma_engine import dharma_engine
from .authorization import authorization_layer
from .safety_layer import safety_layer
from .gita_engine import gita_engine
from .tool_executor import tool_executor
from .iam_module import iam_module
from .zero_trust_engine import zero_trust_engine
from .memory_system import memory_system
from .planning_engine import planning_engine
from .knowledge_base import knowledge_base
from .error_handler import ErrorHandler
from vrin_SOC.autonomous.goals import GoalEngine
from vrin_SOC.autonomous.planner import Planner
from vrin_SOC.autonomous.policy import AutonomyPolicy
from vrin_SOC.autonomous.scheduler import Scheduler
from vrin_SOC.autonomous.agent import autonomous_agent
from vrin_SOC.autonomous.state_manager import state_manager
from vrin_SOC.autonomous.task_manager import task_manager
from vrin_SOC.autonomous.models import AutonomyLevel
from vrin_SOC.hive.coordinator import hive
from vrin_SOC.core.daily_talk import DailyTalk
from vrin_SOC.dev.ollama_dev import OllamaDev

# Agents will be imported lazily to avoid circular imports
class Brain:
    """
    Central AI orchestrator - Vrindha
    """

    def __init__(self):
        state = state_manager.get_state()
        self.mode = state.get("current_mode", "defensive")
        self.pending_confirmations = {}  # store commands awaiting confirmation
        self.last_command_id = 0
        self.goal_engine = GoalEngine()
        self.autonomy_planner = Planner()
        self.policy = AutonomyPolicy()
        self.scheduler = Scheduler()
        self.task_manager = task_manager
        self.autonomous_agent = autonomous_agent
        self.state_manager = state_manager
        self.hive = hive
        if not self.autonomous_agent.active or self.autonomous_agent.emergency_stopped:
            self.mode = "defensive"
        else:
            self.mode = self.autonomous_agent.current_mode or self.mode
        self.daily_mode = False
        self.daily_talk = DailyTalk()
        self.dev_mode = False
        self.dev_assistant = OllamaDev()
        recovery_result = self.scheduler.recover_stuck_tasks()
        print(f"[Brain] Vrindha AI SOC System initialized in {self.mode.upper()} MODE. Autonomous recovery: {recovery_result.get('status')}")

    def _parse_nmap_command(self, command: str) -> tuple:
        """Parse nmap command to extract target, flags, and scan type.
        
        Returns: (target, flags_list, scan_type_str)
        """
        lower = command.lower().strip()
        
        # Remove 'nmap' prefix if present
        if lower.startswith('nmap '):
            lower = lower[5:].strip()
        
        # Known scan type presets
        preset_map = {
            'syn': 'syn', 'syn stealth': 'syn', 'stealth': 'syn',
            'tcp connect': 'tcp', 'tcp': 'tcp',
            'udp': 'udp', 'udp scan': 'udp',
            'ack': 'ack', 'ack scan': 'ack',
            'null': 'null', 'null scan': 'null',
            'fin': 'fin', 'fin scan': 'fin',
            'xmas': 'xmas', 'xmas scan': 'xmas',
            'ping': 'ping', 'ping scan': 'ping',
            'no ping': 'no-ping', 'no-ping': 'no-ping',
            'syn ping': 'syn-ping', 'syn-ping': 'syn-ping',
            'ack ping': 'ack-ping', 'ack-ping': 'ack-ping',
            'udp ping': 'udp-ping', 'udp-ping': 'udp-ping',
            'arp ping': 'arp-ping', 'arp-ping': 'arp-ping',
            'version': 'version', 'version detect': 'version',
            'os detect': 'os-detect', 'os': 'os-detect',
            'aggressive': 'aggressive', 'aggressive scan': 'aggressive',
            'paranoid': 'paranoid', 'sneaky': 'sneaky',
            'polite': 'polite', 'normal': 'normal',
            'insane': 'insane',
            'scripts': 'scripts', 'script scan': 'scripts',
            'vuln': 'vuln', 'vuln scan': 'vuln',
            'fast': 'fast', 'fast scan': 'fast',
            'all ports': 'all-ports', 'all-ports': 'all-ports',
            'fragment': 'fragment',
        }
        
        # Check for preset keywords in command
        scan_type = None
        for keyword, preset in preset_map.items():
            if keyword in lower:
                scan_type = preset
                break
        
        # Extract target (IP or domain)
        target = self.extract_target(command)
        
        # If no preset matched, check for raw flags
        flags = None
        if not scan_type:
            # Look for -sV, -sS, -O, -A, -T4, -p, etc.
            import re
            flag_pattern = r'(-[a-zA-Z](?:\s+\S+)?|--[a-z-]+(?:=\S+)?)'
            matches = re.findall(flag_pattern, command)
            if matches:
                flags = matches
        
        return target, flags, scan_type

    def _is_concrete_team_command(self, command: str) -> bool:
        lower = command.lower()
        markers = (
            "scan network", "nmap", "whois", "nikto", "gobuster", "dirb", "amass",
            "sublist3r", "tcpdump", "hashcat", "exploit", "metasploit",
            "detect threat", "block ip", "firewall", "rootkit", "ids ", "idps",
            "show log", "siem", "incident response", "analyze anomaly", "risk score",
            "endpoint",
        )
        if lower.startswith("ids") or lower.startswith("idps"):
            return True
        return any(marker in lower for marker in markers)

    def pending_for(self, session_id: str = "cli"):
        """Return the live pending Red Team confirmation for a session, if any."""
        pending = self.pending_confirmations.get(session_id)
        if not pending:
            return None
        created = datetime.fromisoformat(pending["timestamp"])
        if (datetime.now() - created).total_seconds() > 300:
            self.pending_confirmations.pop(session_id, None)
            return None
        return pending

    def _is_admin_user(self, user_token: str = None) -> bool:
        """Check if user is admin for unrestricted access as per user request"""
        if not user_token:
            return False
        try:
            import json
            from pathlib import Path
            users_file = Path(__file__).resolve().parent.parent / "database" / "users.json"
            if users_file.exists():
                users = json.loads(users_file.read_text(encoding='utf-8'))
                user_data = users.get(user_token, {})
                if user_data.get("role") == "admin":
                    return True
                for uname, udata in users.items():
                    if uname == user_token and udata.get("role") == "admin":
                        return True
        except Exception:
            pass
        return False

    def _is_admin_session(self, session_id: str = None, user_token: str = None) -> bool:
        return self._is_admin_user(user_token)

    def classify_command(self, command: str) -> Dict:
        """Classify as red/blue per blueprint"""
        cmd_lower = command.lower()

        red_keywords = ["scan", "nmap", "recon", "vulnerability", "nikto", "gobuster", "dirb", "amass", "sublist3r", "whois", "wireshark", "tcpdump", "metasploit", "hashcat", "hydra", "burpsuite", "exploit", "penetration", "hack", "crack", "bypass", "ddos", "deface"]
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
        """Extract target IP/domain from command. Supports IPv4 and IPv6."""
        # IPv6 regex (full and compressed forms)
        ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|\b::\b"
        match = re.search(ipv6_pattern, command)
        if match:
            return match.group(0)
        # IPv4 regex
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
        # Handle tcpdump interface extraction: "tcpdump eth0" -> "eth0"
        if "tcpdump" in command.lower():
            lower = command.lower()
            idx = lower.find("tcpdump")
            after = command[idx + 7:].strip()
            if after:
                return after.split()[0]
        return ""

    def process(self, command: str, auto_confirm: bool = False, user_token: str = None, session_id: str = "cli") -> Dict[str, Any]:
        """
        Main process method per blueprint
        Handles pending confirmation flow
        """
        try:
            command = command.strip()
            if not command:
                return {"mode": "blue", "action": "empty", "status": "error", "message": "Empty command", "data": {}}

            # Log interaction for self-improvement
            try:
                from vrin_SOC.dev.self_improvement import get_improvement_engine
                improvement_engine = get_improvement_engine()
            except Exception:
                improvement_engine = None

            # Confirmations are isolated by authenticated API user (or the CLI
            # session) so one user can never approve another user's operation.
            pending = self.pending_confirmations.get(session_id)
            if pending:
                created = datetime.fromisoformat(pending["timestamp"])
                if (datetime.now() - created).total_seconds() > 300:
                    self.pending_confirmations.pop(session_id, None)
                    if command.lower() in ["yes", "y", "confirm", "proceed"]:
                        return {"mode": "red", "action": "confirmation_expired", "status": "denied", "message": "Confirmation expired; submit the original command again", "data": {}}
                    pending = None
            if command.lower() in ["yes", "y", "confirm", "proceed"] and pending:
                self.pending_confirmations.pop(session_id, None)
                return self._execute_confirmed(pending["original_command"], pending)

            if command.lower() in ["no", "n", "cancel", "abort"] and pending:
                self.pending_confirmations.pop(session_id, None)
                return {"mode": "red", "action": "cancelled", "status": "success", "message": "Action cancelled by user per Red Team safety", "data": {}}

            # Daily Talk mode: enter with 'daily' or 'talk'
            if command.lower() in ["daily", "talk"]:
                self.daily_mode = True
                greeting = self.daily_talk.enter()
                return {"mode": "daily", "action": "daily_talk_enter", "status": "success", "message": greeting, "data": {"knowledge_topics": len(self.daily_talk.knowledge_base)}}

            # Daily Talk mode: exit with 'back'/'exit'/'quit'
            if self.daily_mode and command.lower() in ["back", "exit", "quit"]:
                exit_msg = self.daily_talk.exit()
                self.daily_mode = False
                return {"mode": "daily", "action": "daily_talk_exit", "status": "success", "message": exit_msg, "data": {}}

            # Daily Talk mode: route all other messages to daily_talk.chat()
            if self.daily_mode:
                chat_result = self.daily_talk.chat(command, self.daily_talk.conversation_history)
                return {"mode": "daily", "action": "daily_talk_chat", "status": "success", "message": chat_result["response"], "data": {"knowledge_shared": chat_result["knowledge_shared"], "topic": chat_result["topic"]}}

            # Dev Assistant mode: enter with 'dev' or 'develop'
            if command.lower() in ["dev", "develop", "assistant"]:
                self.dev_mode = True
                greeting = self.dev_assistant.enter()
                return {"mode": "dev", "action": "dev_enter", "status": "success", "message": greeting, "data": {}}

            # Dev Assistant mode: exit with 'back'/'exit'/'quit'
            if self.dev_mode and command.lower() in ["back", "exit", "quit"]:
                exit_msg = self.dev_assistant.exit_dev()
                self.dev_mode = False
                return {"mode": "dev", "action": "dev_exit", "status": "success", "message": exit_msg, "data": {}}

            # Dev Assistant mode: route all other messages to dev_assistant.process()
            if self.dev_mode:
                result = self.dev_assistant.process(command)
                if result.get("exit"):
                    self.dev_mode = False
                return {"mode": "dev", "action": "dev_chat", "status": "success", "message": result["output"], "data": {"files_modified": result.get("files_modified", [])}}

            # Self-Improvement commands
            if command.lower().startswith("improve "):
                return self._handle_improve_command(command[8:].strip())

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
                agent_state = self.autonomous_agent.status()
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
                        "autonomous_agent": agent_state,
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

            # Zero Trust check first - Admin unrestricted bypass
            zt_result = zero_trust_engine.evaluate_command(command)
            if zt_result.get("access_decision") == "deny" and zt_result.get("trust_score", 100) < 20:
                if self._is_admin_user(user_token):
                    pass  # Admin unrestricted: bypass
                else:
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

            # Safety Layer evaluation - pass user_token for admin unrestricted check
            safety = safety_layer.evaluate_request(command, target, mode=mode, user_token=user_token)

            # A Dharma denial is final regardless of how the command was classified.
            # This prevents harmful commands with no known tool keyword from falling
            # through to the generic Blue Team handler.
            # Admin unrestricted: Admin can bypass Dharma denial with warning as per user request
            if safety.get("decision") == "deny":
                if self._is_admin_user(user_token):
                    pass
                else:
                    dharma = safety.get("dharma", {})
                    return {
                        "mode": mode,
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

            # Memory: retrieve similar cases
            similar_cases = memory_system.retrieve_similar(command)

            # Planning engine suggestions
            plan = planning_engine.plan(command)

            # Runtime autonomy commands
            runtime_result = self._handle_autonomy_runtime(command, user_token)
            if runtime_result is not None:
                return runtime_result

            # Hive coordination commands
            hive_result = self._handle_hive_commands(command)
            if hive_result is not None:
                return hive_result

            # Autonomous goal evaluation. Concrete Red/Blue operations must not
            # be swallowed by keyword overlap such as "detect threats".
            goal_meta = self.goal_engine.classify_goal(command)
            if goal_meta.get("category") != "unknown" and not self._is_concrete_team_command(command):
                return self._handle_autonomous_goal(command, goal_meta, classification, safety, similar_cases, plan)

            # Route based on mode
            if mode == "red":
                return self._handle_red_team(command, target, classification, safety, similar_cases, plan, auto_confirm, user_token, session_id)
            else:
                return self._handle_blue_team(command, target, classification, safety, similar_cases, plan)

        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain.process")
            return {
                "mode": "unknown",
                "action": "error",
                "status": "error",
                "message": "Brain could not process the command",
                "data": err,
                "gita_guidance": gita_engine.get_ethical_guidance("defense")
            }

    def _handle_red_team(self, command: str, target: str, classification: Dict, safety: Dict, similar: Dict, plan: Dict, auto_confirm: bool, user_token, session_id: str) -> Dict:
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

        # Red Team operations always require a separate confirmation request.
        # The legacy auto_confirm argument is intentionally ignored for non-admin.
        # Admin unrestricted: Admin can use auto_confirm to bypass as per user request
        if auto_confirm and self._is_admin_user(user_token):
            return self._execute_confirmed(command, {"target": target, "classification": classification, "safety": safety, "timestamp": __import__('datetime').datetime.now().isoformat()})

        self.last_command_id += 1
        self.pending_confirmations[session_id] = {
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

    def _build_red_preview(self, command: str, target: str) -> str:
        cmd_lower = command.lower()
        if "nmap" in cmd_lower or "scan network" in cmd_lower:
            # Detect scan type for preview
            scan_type_map = {
                'syn': 'SYN Stealth', 'tcp': 'TCP Connect', 'udp': 'UDP',
                'ack': 'ACK', 'null': 'Null', 'xmas': 'Xmas', 'fin': 'FIN',
                'version': 'Version Detect', 'os-detect': 'OS Detection',
                'aggressive': 'Aggressive (-A)', 'fast': 'Fast (-F)',
                'all-ports': 'All Ports (-p-)', 'vuln': 'Vulnerability (NSE)',
                'scripts': 'Scripts (-sC)', 'ping': 'Ping Scan (-sn)',
                'fragment': 'Fragmented (-f)', 'paranoid': 'Paranoid (-T0)',
                'sneaky': 'Sneaky (-T1)', 'polite': 'Polite (-T2)',
                'insane': 'Insane (-T5)',
            }
            scan_desc = "Standard scan"
            for keyword, desc in scan_type_map.items():
                if keyword in cmd_lower:
                    scan_desc = desc
                    break
            return f"Run {scan_desc} nmap on {target or '127.0.0.1'}"
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
            from vrin_SOC.agents.recon_agent import recon_agent
            from vrin_SOC.agents.vuln_agent import vuln_agent
            from vrin_SOC.agents.threat_agent import threat_agent
            from vrin_SOC.agents.siem_agent import siem_agent

            result_data = {}
            message = ""

            # Route to appropriate agent per 30-day and startup blueprints
            if "scan network" in cmd_lower or "nmap" in cmd_lower:
                # Parse for flags/scan_type
                from vrin_SOC.tools.nmap_tool import run_nmap
                target, flags, scan_type = self._parse_nmap_command(command)
                result_data = run_nmap(target or "127.0.0.1", flags=flags, scan_type=scan_type)
                scan_desc = result_data.get("scan_type", "Standard")
                message = f"Nmap {scan_desc} scan completed on {target}"
            elif "whois" in cmd_lower:
                from vrin_SOC.tools.whois_tool import run_whois
                result_data = run_whois(target if target else "google.com")
                message = f"Whois lookup for {target}"
            elif "vulnerab" in cmd_lower or "nikto" in cmd_lower:
                result_data = vuln_agent.run(target)
                message = f"Vulnerability scan on {target}"
            elif "gobuster" in cmd_lower:
                from vrin_SOC.tools.gobuster_tool import run_gobuster
                result_data = run_gobuster(target)
                message = f"Gobuster scan on {target}"
            elif "dirb" in cmd_lower:
                from vrin_SOC.tools.dirb_tool import run_dirb
                result_data = run_dirb(target)
                message = f"Dirb scan on {target}"
            elif "amass" in cmd_lower:
                from vrin_SOC.tools.amass_tool import run_amass
                result_data = run_amass(target)
                message = f"Amass enum on {target}"
            elif "sublist3r" in cmd_lower:
                from vrin_SOC.tools.sublist3r_tool import run_sublist3r
                result_data = run_sublist3r(target)
                message = f"Sublist3r on {target}"
            elif "tcpdump" in cmd_lower:
                from vrin_SOC.tools.tcpdump_tool import run_tcpdump
                result_data = run_tcpdump(target or "eth0")
                message = f"tcpdump on {target}"
            elif "hashcat" in cmd_lower:
                from vrin_SOC.tools.hashcat_tool import run_hashcat_assistant
                result_data = run_hashcat_assistant(command)
                message = "Hashcat assistant - command suggested, not auto-executed per strict control"
            elif "exploit" in cmd_lower or "metasploit" in cmd_lower:
                from vrin_SOC.agents.exploit_assistant import exploit_assistant
                result_data = exploit_assistant.suggest_exploit(command, target)
                message = "Exploit assistant — suggestion only, no exploit was executed"
            else:
                # Generic recon
                result_data = recon_agent.run(target)
                message = f"Recon scan on {target}"

            execution_status = result_data.get("status") if isinstance(result_data, dict) else None
            if execution_status == "simulated":
                message = f"[SIMULATION] {message}; no system change was made"
            elif execution_status == "error":
                message = f"Tool execution failed: {message}"

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
                from vrin_SOC.database.db import add_log
                add_log(command, str(result_data)[:2000], "Medium")
            except Exception as e:
                # best‑effort: continue without logging
                pass

            # Threat analysis on result
            threat_analysis = threat_agent.analyze(str(result_data))

            # Build scan summary for result message
            scan_summary = ""
            if isinstance(result_data, dict):
                if result_data.get("type") == "network_scan":
                    scan_summary = _build_network_scan_summary(result_data)
                elif result_data.get("type") == "vulnerability_scan":
                    scan_summary = _build_vuln_scan_summary(result_data)

            return {
                "mode": "red",
                "action": "executed",
                # Do not report a confirmed operation as successful when the
                # selected tool actually failed (for example, a permissions
                # error or a timeout).
                "status": "error" if execution_status == "error" else "success",
                "message": message + f" | Threat Level: {threat_analysis.get('threat_level','Low')}",
                "data": {
                    "result": result_data,
                    "threat_analysis": threat_analysis,
                    "target": target,
                    "scan_summary": scan_summary,
                    "gita_guidance": gita_engine.get_ethical_guidance("defense")
                }
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain._execute_confirmed")
            return {
                "mode": "red",
                "action": "execution_failed",
                "status": "error",
                "message": "Execution failed after confirmation",
                "data": err
            }

    def _build_network_scan_summary(self, result_data: dict) -> str:
        """Build a summary string for network scan results."""
        lines = []
        if result_data.get("target_ip_type"):
            lines.append(f"IP Type: {result_data['target_ip_type']}")
        if result_data.get("target_reverse_dns"):
            lines.append(f"Reverse DNS: {result_data['target_reverse_dns']}")
        if result_data.get("scan_duration_seconds"):
            lines.append(f"Duration: {result_data['scan_duration_seconds']}s")
        if result_data.get("open_ports") is not None:
            lines.append(f"Open: {result_data['open_ports']}, Filtered: {result_data.get('filtered_ports', 0)}, Closed: {result_data.get('closed_ports', 0)}")
        if result_data.get("os_guess"):
            lines.append(f"OS: {result_data['os_guess']}")
        return " | ".join(lines)

    def _build_vuln_scan_summary(self, result_data: dict) -> str:
        """Build a summary string for vulnerability scan results."""
        lines = []
        if result_data.get("target_ip_type"):
            lines.append(f"IP Type: {result_data['target_ip_type']}")
        if result_data.get("target_reverse_dns"):
            lines.append(f"Reverse DNS: {result_data['target_reverse_dns']}")
        if result_data.get("scan_duration_seconds"):
            lines.append(f"Duration: {result_data['scan_duration_seconds']}s")
        if result_data.get("highest_severity"):
            lines.append(f"Highest Severity: {result_data['highest_severity']}")
        if result_data.get("severity_summary"):
            s = result_data["severity_summary"]
            lines.append(f"Crit:{s.get('Critical',0)} High:{s.get('High',0)} Med:{s.get('Medium',0)} Low:{s.get('Low',0)}")
        return " | ".join(lines)

    def _handle_blue_team(self, command: str, target: str, classification: Dict, safety: Dict, similar: Dict, plan: Dict) -> Dict:
        """Blue Team → CAN be automated per blueprint"""
        try:
            from vrin_SOC.agents.threat_agent import threat_agent
            from vrin_SOC.agents.siem_agent import siem_agent
            from vrin_SOC.automation.actions import automation_actions

            cmd_lower = command.lower()

            # Threat detection
            if any(k in cmd_lower for k in ["threat", "attack", "breach", "malware"]):
                # Analyze text for threat levels per Day 17, then convert the
                # answer into a risk score instead of a binary yes/no decision.
                threat_result = threat_agent.analyze(command)
                from vrin_SOC.ml.risk_scoring import risk_scoring
                from vrin_SOC.automation.response_engine import response_engine

                risk_assessment = risk_scoring.score({
                    "ip": target or "",
                    "source_ip": target or "",
                    "command": command,
                    "severity": threat_result.get("threat_level"),
                    "threat_level": threat_result.get("threat_level"),
                    "risk_level": threat_result.get("risk_level"),
                    "confidence": threat_result.get("confidence"),
                    "indicators": threat_result.get("indicators", []),
                    "failed_login_attempts": threat_result.get("failed_login_attempts", 0),
                    "suspicious_ports": threat_result.get("suspicious_ports", []),
                })

                response_recommendation = None
                try:
                    from vrin_SOC.database.db import add_threat
                    add_threat(
                        ",".join(threat_result.get("indicators") or [threat_result.get("threat") or "analysis"]),
                        target or "",
                        risk_assessment.get("risk_level", threat_result.get("risk_level", "LOW")),
                        command,
                    )
                except Exception:
                    pass

                # High-risk/high-impact responses are no longer auto-blocked.
                # They are parked at the human-validation gate.
                if risk_assessment.get("requires_human_validation"):
                    response_recommendation = response_engine.respond({
                        "alert_id": f"brain-{self.last_command_id + 1}",
                        "source_ip": target or "",
                        "command": command,
                        "threat": threat_result,
                        "risk_assessment": risk_assessment,
                    })
                    memory_system.save_memory({
                        "event_type": "human_validation_required",
                        "threat": command,
                        "action_taken": "awaiting_human_validation",
                        "outcome": str(response_recommendation),
                        "risk_level": risk_assessment.get("risk_level", "High"),
                        "timestamp": datetime.now().isoformat(),
                    })

                # Anti-hallucination, evidence-grounded analysis (Vrindha AI
                # contract): FACT/INFERENCE/UNKNOWN separation, verified TI
                # state, explainable risk+confidence, structured report, and a
                # persisted audit row. Additive: failures never break the
                # legacy threat-detection response.
                evidence_analysis = None
                try:
                    from vrin_SOC.coordination.evidence_analysis import render_report, vrindha_ai
                    from vrin_SOC.coordination.schemas import SecurityEvent as _SecurityEvent

                    analysis_event = _SecurityEvent(
                        event_type="security_event",
                        entity={"ip": target} if target else {},
                        data={
                            "command": command,
                            "threat_level": threat_result.get("threat_level"),
                            "risk_level": threat_result.get("risk_level"),
                            "confidence": threat_result.get("confidence"),
                            "indicators": threat_result.get("indicators") or [],
                            "failed_login_attempts": threat_result.get("failed_login_attempts") or 0,
                            "suspicious_ports": threat_result.get("suspicious_ports") or [],
                            "threat_intelligence": threat_result.get("threat_intelligence") or {},
                        },
                        severity=str(threat_result.get("risk_level") or threat_result.get("threat_level") or "low").lower(),
                    )
                    analysis_result = vrindha_ai.analyze(analysis_event)
                    if hasattr(analysis_result, "analysis_id"):
                        evidence_analysis = {
                            "analysis_id": analysis_result.analysis_id,
                            "analysis": analysis_result.model_dump(mode="json"),
                            "report": render_report(analysis_result),
                        }
                except Exception:  # noqa: BLE001 — analysis is advisory, not blocking
                    evidence_analysis = None

                return {
                    "mode": "blue",
                    "action": "threat_detection",
                    "status": "success",
                    "message": (
                        f"Threat analysis completed - Risk Score: {risk_assessment.get('risk_score')}/100 "
                        f"({risk_assessment.get('risk_level')}) | Confidence: {risk_assessment.get('confidence_score')}/100 | "
                        f"Human validation required: {risk_assessment.get('requires_human_validation')}"
                    ),
                    "data": {
                        "threat": threat_result,
                        "risk_assessment": risk_assessment,
                        "response_recommendation": response_recommendation,
                        # Legacy key retained for clients; no containment action
                        # is executed here unless a human validates it later.
                        "automated_action": response_recommendation,
                        "evidence_analysis": evidence_analysis,
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
                ip_to_block = target
                if not ip_to_block:
                    return {
                        "mode": "blue",
                        "action": "block_ip",
                        "status": "error",
                        "message": "Provide an IP to block, e.g. 'block ip 192.168.1.50'",
                        "data": {},
                    }
                result = automation_actions.block_ip(ip_to_block)
                result_status = result.get("status")
                succeeded = result_status != "error"
                message = result.get("message", "Could not block IP")
                if succeeded:
                    try:
                        from vrin_SOC.database.db import add_blocked_ip
                        add_blocked_ip(ip_to_block, f"Operator block: {command[:160]}")
                    except Exception:
                        pass
                if succeeded and result_status != "simulated":
                    message = f"Automated defensive action: Blocked IP {ip_to_block}"
                return {
                    "mode": "blue",
                    "action": "block_ip",
                    "status": "success" if succeeded else "error",
                    "message": message,
                    "data": result
                }

            if "firewall" in cmd_lower or "fail2ban" in cmd_lower:
                from vrin_SOC.automation.firewall import firewall_module
                result = firewall_module.check_and_block()
                return {
                    "mode": "blue",
                    "action": "firewall_check",
                    "status": "success",
                    "message": "Firewall auto-response check completed",
                    "data": result
                }

            if "rootkit" in cmd_lower or "rkhunter" in cmd_lower or "chkrootkit" in cmd_lower:
                from vrin_SOC.automation.rootkit_scanner import rootkit_scanner
                result = rootkit_scanner.scan()
                return {
                    "mode": "blue",
                    "action": "rootkit_scan",
                    "status": "success",
                    "message": "Endpoint rootkit scan completed",
                    "data": result
                }

            if any(k in cmd_lower for k in ["incident response", "security incident", "forensic", "endpoint security", "endpoint scan", "contain", "isolate"]):
                from vrin_SOC.agents.endpoint_security import endpoint_security
                from vrin_SOC.automation.ids_monitor import ids_monitor
                from vrin_SOC.automation.firewall import firewall_module
                from vrin_SOC.automation.response_engine import response_engine

                endpoint_result = endpoint_security.scan()
                idps_result = ids_monitor.monitor()
                firewall_result = firewall_module.check_and_block()
                response_result = response_engine.respond({
                    "risk_level": "HIGH" if "incident response" in cmd_lower or "security incident" in cmd_lower else "MEDIUM",
                    "source_ip": target or "",
                    "command": command,
                })

                return {
                    "mode": "blue",
                    "action": "incident_response",
                    "status": "success",
                    "message": "Incident response workflow executed with endpoint security, IDPS monitoring, firewall review, and safe response recommendation",
                    "data": {
                        "endpoint_scan": endpoint_result,
                        "idps_monitor": idps_result,
                        "firewall_check": firewall_result,
                        "response_engine": response_result,
                        "safety": safety,
                        "gita_guidance": gita_engine.get_ethical_guidance("defense")
                    }
                }

            if any(k in cmd_lower for k in ["idps", "ids", "snort", "suricata"]):
                from vrin_SOC.automation.ids_monitor import ids_monitor
                result = ids_monitor.monitor()
                return {
                    "mode": "blue",
                    "action": "idps_monitor",
                    "status": "success",
                    "message": "IDPS protection completed - Blue Team automated",
                    "data": result
                }

            if "anomaly" in cmd_lower or "risk" in cmd_lower:
                from vrin_SOC.ml.anomaly_detector import anomaly_detector
                from vrin_SOC.ml.risk_scoring import risk_scoring
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

    def _handle_autonomous_goal(self, command: str, goal_meta: dict, classification: dict, safety: dict, similar: dict, plan: dict) -> dict:
        """Create a persisted autonomous goal and structured task plan."""
        try:
            goal_record = self.task_manager.create_goal(goal_meta)
            task_definitions = self.autonomy_planner.plan_goal(goal_meta)
            stored_tasks = self.task_manager.create_tasks(goal_record["id"], task_definitions)

            goal_decision = self.policy.evaluate_goal(goal_meta)
            tasks_decisions = []
            requires_approval = goal_decision["requires_approval"]

            for task in task_definitions:
                task_policy = self.policy.evaluate_task(task, goal_meta["autonomy_level"])
                if task_policy["requires_approval"]:
                    requires_approval = True
                tasks_decisions.append({
                    "task_id": task["task_id"],
                    "description": task["description"],
                    "risk": task["risk"],
                    "decision": task_policy["decision"],
                    "requires_approval": task_policy["requires_approval"],
                    "reason": task_policy["reason"],
                })

            status = "waiting_approval" if requires_approval else "planned"
            if status != goal_record["status"]:
                self.task_manager.update_goal_status(goal_record["id"], status)

            return {
                "mode": "autonomous",
                "action": "goal_planned",
                "status": "success",
                "message": f"Goal accepted and decomposed into {len(stored_tasks)} structured tasks. {'Approval required.' if requires_approval else 'No approval required for planning.'}",
                "data": {
                    "goal": goal_record,
                    "goal_meta": goal_meta,
                    "goal_policy": goal_decision,
                    "tasks": stored_tasks,
                    "task_policy": tasks_decisions,
                    "autonomy_mode": goal_meta.get("autonomy_level"),
                    "plan_preview": plan,
                    "safety": safety,
                    "similar_cases": similar,
                }
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "Brain._handle_autonomous_goal")
            return {
                "mode": "autonomous",
                "action": "goal_planning_failed",
                "status": "error",
                "message": "Failed to generate autonomous goal plan.",
                "data": err,
            }

    def _handle_autonomy_runtime(self, command: str, user_token: str = None) -> dict | None:
        lower = command.lower().strip()

        # Autonomous agent lifecycle commands
        if lower in ["start autonomous agent", "start autonomy", "enable autonomous mode"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "start_denied", "status": "denied", "message": "Only admin may start autonomous operations."}
            result = self.autonomous_agent.start(mode="autonomous")
            self.mode = "autonomous" if result.get("status") == "success" else self.mode
            return {"mode": "autonomous", "action": "start_agent", "status": result.get("status"), "message": result.get("message"), "data": result}

        if lower in ["stop autonomous agent", "stop autonomy", "disable autonomous mode"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "stop_denied", "status": "denied", "message": "Only admin may stop autonomous operations."}
            result = self.autonomous_agent.stop()
            self.mode = "defensive"
            return {"mode": "autonomous", "action": "stop_agent", "status": result.get("status"), "message": result.get("message"), "data": result}

        if lower in ["autonomous heartbeat", "heartbeat", "pulse"]:
            result = self.autonomous_agent.heartbeat()
            return {"mode": "autonomous", "action": "heartbeat", "status": result.get("status"), "message": result.get("message"), "data": result}

        if lower in ["emergency stop", "halt autonomy", "stop all autonomous operations"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "emergency_stop_denied", "status": "denied", "message": "Only admin may trigger emergency stop."}
            result = self.autonomous_agent.emergency_stop()
            self.mode = "defensive"
            return {"mode": "autonomous", "action": "emergency_stop", "status": result.get("status"), "message": result.get("message"), "data": result}

        if lower in ["reset emergency stop", "reset autonomy", "resume autonomous operations"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "reset_emergency_denied", "status": "denied", "message": "Only admin may reset emergency stop."}
            return {"mode": "autonomous", "action": "reset_emergency", "status": "success", "message": "Emergency stop reset.", "data": self.autonomous_agent.reset_emergency()}

        if lower.startswith("set autonomous mode") or lower.startswith("set autonomy mode") or lower in ["switch to defensive mode", "switch to autonomous mode", "set defensive mode", "set autonomous mode"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "set_mode_denied", "status": "denied", "message": "Only admin may change autonomous mode."}
            if "defensive" in lower:
                result = self.autonomous_agent.set_mode("defensive")
                self.mode = "defensive"
            elif "autonomous" in lower:
                result = self.autonomous_agent.set_mode("autonomous")
                self.mode = "autonomous"
            else:
                return {"mode": "autonomous", "action": "set_mode_invalid", "status": "error", "message": "Specify 'defensive' or 'autonomous'."}
            return {"mode": self.mode, "action": "set_mode", "status": result.get("status"), "message": result.get("message"), "data": result}

        if lower in ["autonomous agent status", "autonomy status", "agent status"]:
            return {"mode": "autonomous", "action": "status_agent", "status": "success", "message": "Autonomous agent status.", "data": self.autonomous_agent.status()}

        if lower in ["recover autonomous tasks", "recover stuck tasks", "resume pending tasks", "recover pending tasks"]:
            if not self._is_admin_user(user_token):
                return {"mode": "autonomous", "action": "recover_denied", "status": "denied", "message": "Only admin may recover stuck tasks."}
            result = self.scheduler.recover_stuck_tasks()
            return {"mode": "autonomous", "action": "recover_tasks", "status": result.get("status"), "message": "Autonomous task recovery completed.", "data": result}

        # Task execution commands
        if lower.startswith("run autonomous goal") or lower.startswith("execute autonomous goal"):
            try:
                parts = lower.split()
                goal_id = int(parts[-1])
            except Exception:
                return {"mode": "autonomous", "action": "invalid_goal_id", "status": "error", "message": "Specify a numeric goal id at end of the command."}
            if not self.autonomous_agent.active or self.autonomous_agent.emergency_stopped:
                return {"mode": "autonomous", "action": "runner_unavailable", "status": "denied", "message": "Autonomous agent must be active and not emergency-stopped to run goals."}
            execution = self.scheduler.run_goal(goal_id)
            return {"mode": "autonomous", "action": "goal_executed", "status": "success" if execution.get("status") != "error" else "error", "message": "Autonomous goal execution completed.", "data": execution}

        if lower in ["run pending autonomous tasks", "execute pending tasks", "process pending autonomous tasks"]:
            if not self.autonomous_agent.active or self.autonomous_agent.emergency_stopped:
                return {"mode": "autonomous", "action": "runner_unavailable", "status": "denied", "message": "Autonomous agent must be active and not emergency-stopped to process pending tasks."}
            execution = self.scheduler.run_pending_tasks()
            return {"mode": "autonomous", "action": "pending_tasks_executed", "status": "success", "message": "Pending autonomous tasks executed.", "data": execution}

        return None

    def _handle_hive_commands(self, command: str) -> dict | None:
        """Handle hive-layer coordination commands."""
        lower = command.lower().strip()

        if lower in ["hive status", "hive health", "swarm status", "agent hive"]:
            return {
                "mode": "blue",
                "action": "hive_health",
                "status": "success",
                "message": "Hive coordination layer health report.",
                "data": self.hive.health(),
            }

        if lower in ["hive snapshot", "swarm snapshot", "hive full"]:
            return {
                "mode": "blue",
                "action": "hive_snapshot",
                "status": "success",
                "message": "Full hive snapshot.",
                "data": self.hive.snapshot(),
            }

        if lower in ["hive agents", "list agents", "show agents", "agent list"]:
            return {
                "mode": "blue",
                "action": "hive_agents",
                "status": "success",
                "message": "Registered hive agents.",
                "data": self.hive.list_agents(),
            }

        if lower.startswith("hive reap") or lower == "reap stale agents":
            return {
                "mode": "blue",
                "action": "hive_reap",
                "status": "success",
                "message": "Stale agent heartbeat reaping completed.",
                "data": self.hive.reap_stale(),
            }

        if lower.startswith("hive tasks") or lower == "list hive tasks":
            return {
                "mode": "blue",
                "action": "hive_tasks",
                "status": "success",
                "message": "Hive task queue.",
                "data": self.hive.list_tasks(),
            }

        return None

    def _handle_improve_command(self, subcommand: str) -> Dict[str, Any]:
        """Handle self-improvement commands: improve status, improve run, improve report."""
        try:
            from vrin_SOC.dev.self_improvement import get_improvement_engine
            
            engine = get_improvement_engine()
            
            if subcommand.lower() in ["status", "report"]:
                report = engine.get_improvement_report()
                return {"mode": "blue", "action": "improve_status", "status": "success", "message": report, "data": {}}
            elif subcommand.lower() in ["run", "auto", "improve"]:
                results = engine.auto_improve()
                msg = f"🧠 Self-improvement run complete:\n" + "\n".join(f"  • {a}" for a in results["actions_taken"])
                if results["suggestions"]:
                    msg += "\n\n💡 Suggestions:\n" + "\n".join(f"  • {s}" for s in results["suggestions"])
                return {"mode": "blue", "action": "improve_run", "status": "success", "message": msg, "data": results}
            else:
                return {"mode": "blue", "action": "improve_help", "status": "success",
                        "message": "Usage: improve status | improve report | improve run",
                        "data": {}}
        except Exception as e:
            return {"mode": "blue", "action": "improve_error", "status": "error",
                    "message": f"Self-improvement error: {e}", "data": {}}

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

🐝 HIVE (Agent Coordination):
- hive status - Hive health and agent overview
- hive agents - List all registered agents
- hive snapshot - Full hive point-in-time snapshot
- hive tasks - Show hive task queue
- reap stale agents - Mark offline agents

🕉️ DHARMA ENGINE:
All actions evaluated for ethical compliance per Bhagavad Gita.
Red Team requires explicit "yes" confirmation.

🌸 DAILY TALK (Casual Chat):
- daily / talk - Enter Daily Talk mode for casual conversation
- (type 'back' to exit)

🛡️ DEV ASSISTANT (Developer Mode):
- dev / develop - Enter Dev Assistant for code review, editing, and project management
- (type 'back' to exit)

🧠 SELF-IMPROVEMENT (Learning System):
- improve status - View self-improvement report
- improve run - Run auto-improvement analysis
- improve report - Detailed usage analytics

🌸 DAILY TALK (Cybersecurity Education):
- daily / talk - Enter Daily Talk mode for friendly security learning
- back - Exit Daily Talk mode and return to SOC mode
"""

# Global brain instance
brain = Brain()


def _handle_improve_command(self, subcommand: str) -> Dict[str, Any]:
        """Handle self-improvement commands: improve status, improve run, improve report."""
        try:
            from vrin_SOC.dev.self_improvement import get_improvement_engine
            
            engine = get_improvement_engine()
            
            if subcommand.lower() in ["status", "report"]:
                report = engine.get_improvement_report()
                return {"mode": "blue", "action": "improve_status", "status": "success", "message": report, "data": {}}
            elif subcommand.lower() in ["run", "auto", "improve"]:
                results = engine.auto_improve()
                msg = f"🧠 Self-improvement run complete:\n" + "\n".join(f"  • {a}" for a in results["actions_taken"])
                if results["suggestions"]:
                    msg += "\n\n💡 Suggestions:\n" + "\n".join(f"  • {s}" for s in results["suggestions"])
                return {"mode": "blue", "action": "improve_run", "status": "success", "message": msg, "data": results}
            else:
                return {"mode": "blue", "action": "improve_help", "status": "success",
                        "message": "Usage: improve status | improve report | improve run",
                        "data": {}}
        except Exception as e:
            return {"mode": "blue", "action": "improve_error", "status": "error",
                    "message": f"Self-improvement error: {e}", "data": {}}


def set_autonomy_policy(thresholds: dict) -> None:
    """Update the brain's autonomy policy thresholds from loaded config (Phase 1).

    Called once at startup from main.py after loading autonomy_policy.json.
    """
    if hasattr(brain, "policy") and hasattr(brain.policy, "__dict__"):
        # Store thresholds on the brain for easy access
        brain.autonomy_thresholds = thresholds
        # Also apply to the policy instance if it has relevant attributes
        for key, value in thresholds.items():
            if hasattr(brain.policy, key.upper()):
                setattr(brain.policy, key.upper(), value)
    print(f"[Brain] Autonomy thresholds loaded: {thresholds}")
