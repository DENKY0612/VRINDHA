"""
IAM Module (Advanced - Kali Context) Per START UP.pdf
Identity & Access Security Agent
Responsibilities: Monitor auth attempts, detect brute force (Hydra patterns), enforce MFA, analyze login anomalies
KALI INTEGRATION: Analyze logs from SSH, FTP, web login attempts
"""
from typing import Dict, List
import re
from datetime import datetime
from .error_handler import ErrorHandler

class IAMModule:
    def __init__(self):
        self.failed_attempts = {}  # ip -> count
        self.blocked_ips = set()
    
    def analyze_logs(self, log_text: str) -> Dict:
        try:
            # Simulate parsing SSH logs like "Failed password for user from 192.168.1.10"
            failed_pattern = r"Failed.*?from (\d+\.\d+\.\d+\.\d+)"
            matches = re.findall(failed_pattern, log_text)
            
            for ip in matches:
                self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1
            
            alerts = []
            for ip, count in self.failed_attempts.items():
                if count >= 5:
                    self.blocked_ips.add(ip)
                    alerts.append({
                        "type": "Brute Force Detected",
                        "source_ip": ip,
                        "attempts": count,
                        "risk": "High",
                        "mitigation": f"Block IP {ip} using fail2ban/ufw, enforce MFA"
                    })
            
            return {
                "status": "success",
                "failed_attempts_by_ip": self.failed_attempts,
                "blocked_ips": list(self.blocked_ips),
                "alerts": alerts,
                "mfa_required": len(alerts) > 0
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "IAMModule.analyze_logs")
    
    def detect_brute_force(self, ip: str, attempts: int) -> Dict:
        is_attack = attempts >= 5
        return {
            "attack_type": "Brute Force" if is_attack else "Normal",
            "source_ip": ip,
            "risk_level": "High" if is_attack else "Low",
            "suggested_mitigation": "Block IP, enable MFA, check hydra patterns" if is_attack else "No action",
            "hydra_pattern_detected": is_attack
        }

iam_module = IAMModule()
