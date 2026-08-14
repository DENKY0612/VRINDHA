"""
Zero Trust Engine (Advanced) Per START UP.pdf
Responsibilities: Continuously validate every process, user, device, assign dynamic trust scores
KALI CONTEXT: Monitor privilege escalation, suspicious sudo usage, validate shell commands
"""
from typing import Dict, List
import re
from .error_handler import ErrorHandler

class ZeroTrustEngine:
    def __init__(self):
        self.trust_scores = {}  # entity -> score 0-100
        self.baseline_commands = {"ls", "pwd", "whoami", "nmap", "cat", "grep", "ps"}
        self.suspicious_commands = {"chmod 777", "rm -rf /", "nc -e", "bash -i", "sudo su", "wget http", "curl | sh"}
    
    def evaluate_command(self, command: str, user: str = "default") -> Dict:
        try:
            cmd_lower = command.lower()
            trust_score = 80  # default
            alerts = []
            decision = "allow"
            
            # Check suspicious patterns
            for susp in self.suspicious_commands:
                if susp in cmd_lower:
                    trust_score -= 40
                    alerts.append(f"Suspicious command pattern detected: {susp}")
                    decision = "challenge"
            
            # Privilege escalation check
            if "sudo" in cmd_lower and any(x in cmd_lower for x in ["su", "visudo", "passwd", "shadow"]):
                trust_score -= 30
                alerts.append("Potential privilege escalation via sudo")
                decision = "deny" if trust_score < 30 else "challenge"
            
            # Unusual shell spawn
            if "bash -i" in cmd_lower or "sh -i" in cmd_lower or "nc " in cmd_lower and "-e" in cmd_lower:
                trust_score -= 50
                alerts.append("Reverse shell attempt detected")
                decision = "deny"
            
            # Reduce privileges dynamically
            if trust_score < 50:
                decision = "deny" if trust_score < 20 else "challenge"
            
            self.trust_scores[user] = trust_score
            
            return {
                "user": user,
                "command": command,
                "trust_score": max(0, trust_score),
                "access_decision": decision,
                "alerts": alerts,
                "requires_mfa": trust_score < 60,
                "timestamp": __import__("datetime").datetime.now().isoformat()
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "ZeroTrustEngine.evaluate_command")
    
    def validate_process(self, process_name: str, pid: int = 0) -> Dict:
        known_malicious = {"cryptominer", "keylogger", "ransom", "backdoor"}
        is_suspicious = any(m in process_name.lower() for m in known_malicious)
        return {
            "process": process_name,
            "pid": pid,
            "trust_score": 0 if is_suspicious else 75,
            "decision": "deny" if is_suspicious else "allow",
            "alert": f"Suspicious process {process_name}" if is_suspicious else None
        }

zero_trust_engine = ZeroTrustEngine()
