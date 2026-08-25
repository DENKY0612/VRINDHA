"""WHOIS wrapper with a direct port-43 fallback."""
from datetime import datetime
import shutil

from core.error_handler import ErrorHandler
from core.local_sensors import whois_lookup
from core.tool_executor import tool_executor


def run_whois(domain: str) -> dict:
    try:
        domain = domain or "example.com"
        if shutil.which("whois"):
            result = tool_executor.execute(["whois", domain], tool_name="whois", timeout=20)
            if result.get("status") == "success" and result.get("output"):
                return {
                    "type": "whois",
                    "target": domain,
                    "status": "success",
                    "engine": "whois",
                    "result": result.get("output", "")[:8000],
                    "tool": "whois",
                    "timestamp": datetime.now().isoformat(),
                }
        lookup = whois_lookup(domain)
        return {
            "type": "whois",
            "target": domain,
            "status": lookup.get("status"),
            "engine": lookup.get("engine"),
            "result": lookup.get("result", ""),
            "tool": "python-whois",
            "timestamp": lookup.get("timestamp", datetime.now().isoformat()),
            "error": lookup.get("error", ""),
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_whois")
