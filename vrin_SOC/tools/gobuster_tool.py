"""Gobuster wrapper with an HTTP path-probe fallback."""
from datetime import datetime
from pathlib import Path
import shutil

from core.error_handler import ErrorHandler
from core.local_sensors import http_probe
from core.tool_executor import tool_executor


def run_gobuster(url: str) -> dict:
    try:
        url = url or "http://127.0.0.1"
        if not url.startswith("http"):
            url = f"http://{url}"
        if shutil.which("gobuster"):
            wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ]
            wordlist = next((path for path in wordlists if Path(path).exists()), None)
            if wordlist:
                result = tool_executor.execute(
                    ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "20", "-q"],
                    tool_name="gobuster",
                    timeout=45,
                )
                return {
                    "tool": "gobuster",
                    "target": url,
                    "status": result.get("status"),
                    "engine": "gobuster",
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
            "note": "gobuster not installed; probed common web paths",
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_gobuster")
