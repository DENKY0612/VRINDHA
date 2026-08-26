"""
IDPS Auto Protect (Snort/Suricata Primary Defense) per MASTER BLUEPRINT Blue Additional
Features: detection + protection, alert parsing, safe prevention, adaptive block history
Rules:
- High severity: auto-block source IP if known
- Medium severity: alert + monitor, no immediate block
- Low severity: log only
- Maintain safe simulation when defensive tools are unavailable
"""
import re
import shutil
from datetime import datetime
from typing import Dict, List

from .actions import automation_actions
from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.tool_executor import tool_executor

class IDPSMonitor:
    def __init__(self):
        self.alert_history: Dict[str, List[dict]] = {}
        self.blocked_sources: set[str] = set()

    def monitor(self, interface: str = "eth0", prevent: bool = True) -> dict:
        try:
            alerts = []
            alerts.extend(self._run_suricata(interface))
            alerts.extend(self._run_snort(interface))
            try:
                from vrin_SOC.core.local_sensors import local_listeners
                inventory = local_listeners()
                alerts.append({
                    "tool": "local-sockets",
                    "severity": "Low",
                    "msg": inventory.get("summary", "Local listener inventory"),
                    "src_ip": "",
                    "listeners": inventory.get("listeners", [])[:20],
                })
            except Exception:
                pass
            alerts = [alert for alert in alerts if alert]

            for alert in alerts:
                self._record_alert(alert)

            prevention_actions = self._apply_prevention(alerts, interface) if prevent else []
            self._send_alerts(alerts)

            severity_summary = {
                "High": len([a for a in alerts if a.get("severity") == "High"]),
                "Medium": len([a for a in alerts if a.get("severity") == "Medium"]),
                "Low": len([a for a in alerts if a.get("severity") == "Low"]),
            }

            return {
                "status": "success",
                "mode": "protective",
                "prevention_enabled": prevent,
                "alerts_detected": len(alerts),
                "alerts": alerts,
                "prevention_actions": prevention_actions,
                "severity_summary": severity_summary,
                "message": "IDPS auto-protection completed - alerts detected and defensive actions applied when applicable",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "IDPSMonitor.monitor")

    def _run_suricata(self, interface: str) -> List[dict]:
        if shutil.which("suricata"):
            res = tool_executor.execute(f"suricata -i {interface} -v", tool_name="suricata")
            return self._parse_alert_output(res.get("output", ""), "suricata")

        return [
            {
                "tool": "suricata (unavailable)",
                "severity": "Low",
                "msg": "Suricata is not installed; no live IDS alerts. Local socket inventory used instead.",
                "src_ip": "",
                "simulated": True,
            }
        ]

    def _run_snort(self, interface: str) -> List[dict]:
        if shutil.which("snort"):
            res = tool_executor.execute(
                f"snort -q -A console -c /etc/snort/snort.conf -i {interface} -T",
                tool_name="snort",
            )
            return self._parse_alert_output(res.get("output", ""), "snort")

        return [
            {
                "tool": "snort (unavailable)",
                "severity": "Low",
                "msg": "Snort is not installed; no live IDS alerts.",
                "src_ip": "",
                "simulated": True,
            }
        ]

    def _parse_alert_output(self, output: str, tool: str) -> List[dict]:
        alerts = []
        if not output:
            return [
                {
                    "tool": tool,
                    "severity": "Medium",
                    "msg": f"{tool.capitalize()} produced no explicit alert output",
                    "src_ip": self._find_ip(output) or "",
                }
            ]

        for line in output.splitlines():
            lower = line.lower()
            if not lower.strip():
                continue
            if "alert" in lower or "priority" in lower or "[**]" in line:
                alerts.append(
                    {
                        "tool": tool,
                        "severity": self._normalize_severity(line),
                        "msg": line.strip(),
                        "src_ip": self._find_ip(line),
                    }
                )

        if not alerts:
            alerts.append(
                {
                    "tool": tool,
                    "severity": "Medium",
                    "msg": f"{tool.capitalize()} output parsed without explicit alert lines",
                    "src_ip": self._find_ip(output) or "",
                }
            )

        return alerts

    def _normalize_severity(self, line: str) -> str:
        low_keywords = ["low", "info", "ping"]
        high_keywords = ["high", "critical", "priority: 1", "priority 1"]
        medium_keywords = ["medium", "priority: 2", "priority 2"]

        lowered = line.lower()
        if any(k in lowered for k in high_keywords):
            return "High"
        if any(k in lowered for k in medium_keywords):
            return "Medium"
        if any(k in lowered for k in low_keywords):
            return "Low"
        return "Medium"

    def _find_ip(self, text: str) -> str:
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        return match.group(0) if match else ""

    def _record_alert(self, alert: dict) -> None:
        src_ip = alert.get("src_ip")
        if not src_ip:
            return
        self.alert_history.setdefault(src_ip, []).append(alert)

    def _apply_prevention(self, alerts: List[dict], interface: str) -> List[dict]:
        actions = []
        for alert in alerts:
            src_ip = alert.get("src_ip")
            severity = alert.get("severity", "Medium")
            if alert.get("simulated"):
                actions.append({"action": "log_only", "ip": src_ip or "unknown", "message": "Simulated/unavailable sensor — no block"})
                continue
            if severity == "High" and src_ip:
                if src_ip not in self.blocked_sources:
                    result = automation_actions.block_ip(src_ip)
                    actions.append({"action": "block_ip", "ip": src_ip, "result": result})
                    if result.get("status") in ["success", "simulated"]:
                        self.blocked_sources.add(src_ip)
                        try:
                            from vrin_SOC.database.db import add_blocked_ip
                            add_blocked_ip(src_ip, f"IDPS high-severity: {alert.get('msg','')[:160]}")
                        except Exception:
                            pass
                else:
                    actions.append({"action": "block_ip", "ip": src_ip, "result": {"status": "skipped", "message": "Source already blocked"}})
            elif severity == "Medium":
                actions.append(
                    {
                        "action": "monitor_source",
                        "ip": src_ip or "unknown",
                        "message": "Medium severity alert raised. Continuing observation and logging for further correlation.",
                    }
                )
            else:
                actions.append(
                    {
                        "action": "log_only",
                        "ip": src_ip or "unknown",
                        "message": "Low severity alert recorded for later review.",
                    }
                )

        return actions

    def _send_alerts(self, alerts: List[dict]) -> None:
        for alert in alerts:
            try:
                automation_actions.send_alert(f"IDPS Alert: {alert}")
            except Exception:
                pass

idps_monitor = IDPSMonitor()
ids_monitor = idps_monitor
