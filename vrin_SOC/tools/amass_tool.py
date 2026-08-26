"""Amass wrapper with a DNS prefix fallback."""
from datetime import datetime
import shutil

from core.error_handler import ErrorHandler
from core.local_sensors import dns_prefixes
from core.tool_executor import tool_executor


def run_amass(domain: str) -> dict:
    try:
        domain = domain or "example.com"
        if shutil.which("amass"):
            result = tool_executor.execute(["amass", "enum", "-d", domain], tool_name="amass", timeout=60)
            return {
                "tool": "amass",
                "target": domain,
                "status": result.get("status"),
                "engine": "amass",
                "data": result.get("output", "")[:5000],
                "result": result.get("output", "")[:5000],
                "error": result.get("error", ""),
                "timestamp": datetime.now().isoformat(),
            }
        lookup = dns_prefixes(domain)
        return {
            "tool": "python-dns",
            "target": domain,
            "status": lookup.get("status"),
            "engine": lookup.get("engine"),
            "data": lookup.get("result", ""),
            "result": lookup.get("result", ""),
            "findings": lookup.get("findings", []),
            "error": "",
            "timestamp": lookup.get("timestamp", datetime.now().isoformat()),
            "note": "amass not installed; resolved common DNS prefixes",
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_amass")
