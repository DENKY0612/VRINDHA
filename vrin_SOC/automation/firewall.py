"""Firewall review: failed-login correlation plus persisted blocks."""
import re
from collections import Counter
from datetime import datetime
from typing import Dict
import shutil

from .actions import automation_actions
from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.tool_executor import tool_executor
from vrin_SOC.database.db import add_blocked_ip, get_blocked_ips, get_logs


class FirewallModule:
    def __init__(self):
        self.threshold = 5

    def analyze_logs(self, log_text: str) -> Dict:
        try:
            ips = re.findall(r"Failed.*?from (\d{1,3}(?:\.\d{1,3}){3})", log_text or "", flags=re.IGNORECASE)
            if not ips:
                ips = re.findall(r"failed login.*?(\d{1,3}(?:\.\d{1,3}){3})", log_text or "", flags=re.IGNORECASE)
            counts = Counter(ips)
            blocked = []
            for ip, count in counts.items():
                if count >= self.threshold:
                    result = automation_actions.block_ip(ip)
                    if result.get("status") != "error":
                        add_blocked_ip(ip, f"{count} failed logins exceeding threshold {self.threshold}")
                    blocked.append({
                        "ip": ip,
                        "attempts": count,
                        "action": result,
                        "reason": f"{count} failed logins exceeding threshold {self.threshold}",
                    })
            return {
                "status": "success",
                "failed_counts": dict(counts),
                "blocked": blocked,
                "threshold": self.threshold,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "FirewallModule.analyze_logs")

    def check_and_block(self, log_text: str = None, demo: bool = False) -> Dict:
        try:
            results = {}
            if shutil.which("fail2ban-client"):
                res = tool_executor.execute(["fail2ban-client", "status"], tool_name="fail2ban-client")
                results["fail2ban"] = res.get("output", "")[:1000]
            else:
                results["fail2ban"] = "fail2ban-client not installed"
            if shutil.which("ufw"):
                res = tool_executor.execute(["ufw", "status"], tool_name="ufw")
                results["ufw"] = res.get("output", "")[:1000]
            else:
                results["ufw"] = "ufw not installed"
            if log_text is None:
                rows = get_logs(200)
                log_text = "\n".join(f"{row.get('command','')} {row.get('result','')}" for row in rows)
            if demo:
                log_text = (log_text or "") + ("\nFailed password for root from 192.168.1.50 port 22 sshd\n" * 6)
            analysis = self.analyze_logs(log_text)
            return {
                "status": "success",
                "firewall_status": results,
                "analysis": analysis,
                "blocked_ips": get_blocked_ips(50),
                "demo": demo,
                "message": "Firewall review completed — blocks persist in SIEM",
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "FirewallModule.check_and_block")


firewall_module = FirewallModule()
