import os
import platform
import shutil
import subprocess
from datetime import datetime
from typing import Dict, Any
from core.tool_executor import tool_executor
from automation.firewall import firewall_module
from automation.ids_monitor import ids_monitor
from automation.rootkit_scanner import rootkit_scanner
from ml.anomaly_detector import anomaly_detector
from ml.risk_scoring import risk_scoring
from database.db import get_logs
from core.error_handler import ErrorHandler


class TaskExecutor:
    """Execute structured tasks through safe, allowlisted actions."""

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        action = task.get("tool", task.get("action_type"))
        task_id = task.get("task_id")
        timestamp = datetime.now().isoformat()
        result = {
            "task_id": task_id,
            "status": "error",
            "tool": action,
            "action_type": task.get("action_type"),
            "output": None,
            "error": None,
            "simulated": False,
            "timestamp": timestamp,
        }

        try:
            if action == "system_status":
                result.update(self._system_status())
            elif action == "package_check":
                result.update(self._package_check())
            elif action == "package_update":
                result.update(self._package_update())
            elif action == "service_status":
                result.update(self._service_status())
            elif action == "report_generation":
                result.update(self._generate_report(task))
            elif action == "log_analysis":
                result.update(self._log_analysis())
            elif action == "anomaly_detection":
                result.update(self._anomaly_detection(task))
            elif action == "risk_scoring":
                result.update(self._risk_scoring(task))
            elif action == "firewall_status":
                result.update(self._firewall_status())
            elif action == "ids_status":
                result.update(self._ids_status())
            elif action == "rootkit_scan":
                result.update(self._rootkit_scan())
            elif action == "network_status":
                result.update(self._network_status())
            elif action == "backup":
                result.update(self._backup())
            else:
                return {
                    **result,
                    "status": "error",
                    "error": f"Unsupported task action '{action}'",
                }

            if result.get("status") not in ["success", "simulated"]:
                result["status"] = "error"
            return result
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "TaskExecutor.execute_task")
            return {
                **result,
                "status": "error",
                "error": str(err),
            }

    def _system_status(self) -> Dict[str, Any]:
        info = {
            "platform": platform.platform(),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
        }
        try:
            usage = shutil.disk_usage("/")
            info["disk_total"] = usage.total
            info["disk_used"] = usage.used
            info["disk_free"] = usage.free
        except Exception:
            info["disk_total"] = info["disk_used"] = info["disk_free"] = None

        return {"status": "success", "output": info}

    def _package_check(self) -> Dict[str, Any]:
        if shutil.which("apt"):
            res = tool_executor.execute(["apt", "list", "--upgradable"], tool_name="apt")
            return {
                "status": "success" if res.get("status") == "success" else "simulated",
                "output": res.get("output"),
                "error": res.get("error"),
            }
        return {
            "status": "simulated",
            "simulated": True,
            "output": "[SIMULATION] Package manager check not available. Would inspect apt/dnf/zypper updates.",
        }

    def _package_update(self) -> Dict[str, Any]:
        allow_updates = os.getenv("ALLOW_AUTONOMOUS_UPDATE", "false").lower() == "true"
        if allow_updates and os.geteuid() == 0 and shutil.which("apt"):
            res = tool_executor.execute(["apt", "upgrade", "-y"], tool_name="apt")
            return {
                "status": "success" if res.get("status") == "success" else "error",
                "output": res.get("output"),
                "error": res.get("error"),
            }
        return {
            "status": "simulated",
            "simulated": True,
            "output": "[SIMULATION] Would install approved security updates if autonomous updates were enabled and running as root.",
            "error": None,
        }

    def _service_status(self) -> Dict[str, Any]:
        if shutil.which("systemctl"):
            res = tool_executor.execute(["systemctl", "list-units", "--type=service", "--state=running"], tool_name="systemctl")
            return {"status": "success", "output": res.get("output"), "error": res.get("error")}
        return {"status": "simulated", "simulated": True, "output": "[SIMULATION] No systemctl available. Would list running services."}

    def _generate_report(self, task: Dict[str, Any]) -> Dict[str, Any]:
        logs = get_logs(20)
        report = {
            "goal": task.get("description"),
            "summary": f"Generated report based on {len(logs)} recent log entries.",
            "recent_logs": logs,
        }
        return {"status": "success", "output": report}

    def _log_analysis(self) -> Dict[str, Any]:
        logs = get_logs(50)
        high_risk = [l for l in logs if l.get("risk_level","low").lower() in ["high","critical"]]
        return {"status": "success", "output": {"count": len(logs), "high_risk": len(high_risk), "summary": "Collected security log analysis."}}

    def _anomaly_detection(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            result = anomaly_detector.detect({"task": task.get("description", "" )})
            return {"status": "success", "output": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _risk_scoring(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            result = risk_scoring.score({"task": task.get("description", "")})
            return {"status": "success", "output": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _firewall_status(self) -> Dict[str, Any]:
        result = firewall_module.check_and_block()
        return {"status": "success", "output": result}

    def _ids_status(self) -> Dict[str, Any]:
        result = ids_monitor.monitor()
        return {"status": "success", "output": result}

    def _rootkit_scan(self) -> Dict[str, Any]:
        result = rootkit_scanner.scan()
        return {"status": "success", "output": result}

    def _network_status(self) -> Dict[str, Any]:
        if shutil.which("ss"):
            res = tool_executor.execute(["ss", "-tunlp"], tool_name="ss")
            return {"status": "success", "output": res.get("output"), "error": res.get("error")}
        return {"status": "simulated", "simulated": True, "output": "[SIMULATION] Network connection check not available. Would inspect network sockets."}

    def _backup(self) -> Dict[str, Any]:
        return {
            "status": "simulated",
            "simulated": True,
            "output": "[SIMULATION] Backup / recovery point creation is not implemented in this environment."
        }


task_executor = TaskExecutor()
