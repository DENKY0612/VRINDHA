"""Nikto wrapper with an HTTP path-probe fallback."""
from datetime import datetime
import shutil

from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.local_sensors import http_probe
from vrin_SOC.core.tool_executor import tool_executor


def _findings_from_probe(probe: dict) -> list:
    vulns = []
    for item in probe.get("findings", []):
        path = item.get("path", "")
        status = item.get("status")
        if path in {"/admin", "/login", "/config", "/backup", "/.git/HEAD", "/server-status"}:
            vulns.append({"id": f"PATH-{status}", "name": f"Exposed path {path}", "severity": "Medium", "description": f"HTTP {status} at {path}"})
        elif path == "/robots.txt" and status == 200:
            vulns.append({"id": "INFO-ROBOTS", "name": "robots.txt present", "severity": "Low", "description": "Robots file may disclose hidden paths"})
    return vulns


def run_nikto(target: str = "http://127.0.0.1") -> dict:
    try:
        if not target:
            target = "http://127.0.0.1"
        display = target if target.startswith("http") else f"http://{target}"
        if shutil.which("nikto"):
            result = tool_executor.execute(["nikto", "-h", display], tool_name="nikto", timeout=60)
            return {
                "type": "vulnerability_scan",
                "target": display,
                "status": result.get("status"),
                "engine": "nikto",
                "tool": "nikto",
                "result": result.get("output", "")[:5000],
                "vulnerabilities": [],
                "timestamp": datetime.now().isoformat(),
                "error": result.get("error", ""),
            }
        probe = http_probe(display)
        vulns = _findings_from_probe(probe)
        return {
            "type": "vulnerability_scan",
            "target": display,
            "status": probe.get("status"),
            "engine": probe.get("engine"),
            "tool": "python-http",
            "result": probe.get("result", ""),
            "vulnerabilities": vulns,
            "findings": probe.get("findings", []),
            "timestamp": probe.get("timestamp", datetime.now().isoformat()),
            "note": "nikto not installed; probed common web paths",
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_nikto")
