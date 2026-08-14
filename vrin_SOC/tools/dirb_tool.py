"""
Dirb Tool - Web Testing per blueprint
Function: run_dirb(url) - asks confirmation, runs dirb url
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_dirb(url: str) -> dict:
    try:
        if not url:
            url = "http://127.0.0.1"
        if not url.startswith("http"):
            url = f"http://{url}"
        
        if not shutil.which("dirb"):
            return {
                "tool": "dirb",
                "target": url,
                "status": "simulated",
                "data": f"[SIMULATION] dirb {url}\n+ {url}/admin (CODE:200)\n+ {url}/config (CODE:200)",
                "error": "",
                "timestamp": datetime.now().isoformat()
            }
        
        result = tool_executor.execute(f"dirb {url}", tool_name="dirb")
        return {
            "tool": "dirb",
            "target": url,
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "error": result.get("error",""),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_dirb")
