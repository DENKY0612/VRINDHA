"""
SIEM Agent - Per DAY 20, MASTER BLUEPRINT SIEM LOGGING, START UP SIEM (Kali Log Correlation)
Responsibilities: Collect logs from system logs, tool outputs, correlate events, read logs/log.txt, return all logs, timeline of attack, correlated threats, alerts
Features: get_logs(), add_log(), persistence (file or DB)
"""
from pathlib import Path
from typing import Dict, List
from datetime import datetime
import json


from vrin_SOC.core.error_handler import ErrorHandler

PACKAGE_ROOT = Path(__file__).resolve().parent.parent


class SIEMAgent:
    def __init__(self, log_file: str = None):
        self.name = "SIEMAgent"
        candidate = Path(log_file) if log_file else PACKAGE_ROOT / "logs" / "log.txt"
        self.log_file = candidate if candidate.is_absolute() else PACKAGE_ROOT / candidate
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.write_text("")
    
    def add_log(self, command: str, result: str, risk_level: str = "Low"):
        try:
            timestamp = datetime.now().isoformat()
            entry = f"[{timestamp}] COMMAND: {command} | RESULT: {result[:200]} | RISK: {risk_level}\n"
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(entry)
            # Also try DB
            try:
                from vrin_SOC.database.db import add_log as db_add
                db_add(command, result, risk_level)
            except Exception as e:
                # Best-effort: ignore error
                pass
        except Exception as e:
            ErrorHandler.handle_exception(e, "SIEMAgent.add_log")
    
    def get_logs(self, limit: int = 100) -> Dict:
        try:
            logs = []
            if self.log_file.exists():
                with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    # Get last N lines
                    for line in lines[-limit:]:
                        logs.append(line.strip())
            
            # Also try DB logs
            db_logs = []
            try:
                from vrin_SOC.database.db import get_logs as db_get
                db_logs = db_get(limit)
            except Exception as e:
                # Best-effort: ignore error
                pass
            
            # Correlate events - simple correlation per blueprint
            correlated = self._correlate(logs)
            
            return {
                "agent": self.name,
                "status": "success",
                "logs": logs,
                "count": len(logs),
                "db_logs": db_logs,
                "correlated_threats": correlated,
                "timeline": logs[-10:],  # last 10 as timeline
                "alerts": [c for c in correlated if c.get("risk") in ["HIGH","Critical"]]
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "SIEMAgent.get_logs")
    
    def _correlate(self, logs: List[str]) -> List[Dict]:
        """Simple event correlation"""
        try:
            threats = []
            for log in logs:
                low = log.lower()
                if "failed" in low or "attack" in low:
                    threats.append({"event": log[:100], "type": "authentication_failure", "risk": "MEDIUM"})
                if "malware" in low or "rootkit" in low:
                    threats.append({"event": log[:100], "type": "malware_indicator", "risk": "HIGH"})
                if "nmap" in low or "scan" in low:
                    threats.append({"event": log[:100], "type": "reconnaissance", "risk": "LOW"})
            return threats
        except Exception as e:
            # Return empty list on error; could log via ErrorHandler if needed
            return []

siem_agent = SIEMAgent()
