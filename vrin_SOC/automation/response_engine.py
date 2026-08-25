"""
Response Engine Prompt (Blue Team) - Per MASTER BLUEPRINT
Build Response Engine
INPUT: threat data
ACTIONS: block_ip(ip), kill_process(pid)
RULES: Only for HIGH risk, log all actions, ensure system safety, return action summary
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from automation.actions import automation_actions
from core.error_handler import ErrorHandler
from datetime import datetime

class ResponseEngine:
    def __init__(self):
        self.name = "ResponseEngine"
    
    def respond(self, threat_data: dict) -> dict:
        try:
            risk = threat_data.get("risk_level") or threat_data.get("risk") or threat_data.get("threat_level") or "Low"
            risk = str(risk).upper()
            
            actions_taken = []
            
            # Only for HIGH risk per blueprint
            if risk == "HIGH":
                ip = threat_data.get("source_ip") or threat_data.get("ip") or ""
                if ip:
                    block_result = automation_actions.block_ip(ip)
                    actions_taken.append(block_result)
                    if block_result.get("status") != "error":
                        from database.db import add_blocked_ip
                        add_blocked_ip(ip, f"HIGH risk auto-response: {str(threat_data)[:180]}")
                    alert_result = automation_actions.send_alert(f"HIGH risk threat responded — blocked {ip}")
                    actions_taken.append(alert_result)
                    message = f"HIGH risk detected — defensive block recorded for {ip}"
                else:
                    alert_result = automation_actions.send_alert("HIGH risk threat with no source IP — logged only")
                    actions_taken.append(alert_result)
                    message = "HIGH risk detected but no source IP was supplied, so nothing was blocked"
            elif risk == "MEDIUM":
                # Only alert, not block automatically (per safety)
                alert_result = automation_actions.send_alert(f"MEDIUM risk threat: {threat_data} - Monitoring")
                actions_taken.append(alert_result)
                message = "MEDIUM risk - Alert sent, monitoring (no automatic block for medium)"
            else:
                message = "LOW risk - Logged only, no automated action"
                automation_actions.send_alert(f"LOW risk log: {threat_data}")
            
            return {
                "engine": self.name,
                "status": "success",
                "risk": risk,
                "actions_taken": actions_taken,
                "message": message,
                "timestamp": datetime.now().isoformat(),
                "safety": "Only HIGH risk auto-blocks per blueprint"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "ResponseEngine.respond")

response_engine = ResponseEngine()
