"""Dirb wrapper with an HTTP path-probe fallback."""
from datetime import datetime
import shutil

from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.local_sensors import http_probe
from vrin_SOC.core.tool_executor import tool_executor


def run_dirb(url: str) -> dict:
    try:
        url = url or "http://127.0.0.1"
        if not url.startswith("http"):
            url = f"http://{url}"
        if shutil.which("dirb"):
            result = tool_executor.execute(["dirb", url], tool_name="dirb", timeout=45)
            return {
                "tool": "dirb",
                "target": url,
                "status": result.get("status"),
                "engine": "dirb",
                "data": result.get("output", "")[:5000],
                "result": result.get("output", "")[:5000],
                "error": result.get("error", ""),
                "timestamp": datetime.now().isoformat(),
            }
        probe = http_probe(url)
        return {
            "tool": "python-http",
            "target": url,
            "status": probe.get("status"),
            "engine": probe.get("engine"),
            "data": probe.get("result", ""),
            "result": probe.get("result", ""),
            "findings": probe.get("findings", []),
            "error": "",
            "timestamp": probe.get("timestamp", datetime.now().isoformat()),
            "note": "dirb not installed; probed common web paths",
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_dirb")
