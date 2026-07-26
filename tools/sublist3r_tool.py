"""
Sublist3r Tool - Advanced Recon per blueprint
Function: run_sublist3r(domain) - asks confirmation, runs sublist3r -d domain
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_sublist3r(domain: str) -> dict:
    try:
        if not domain:
            domain = "example.com"
        
        if not shutil.which("sublist3r"):
            # Also check python version
            return {
                "tool": "sublist3r",
                "target": domain,
                "status": "simulated",
                "data": f"[SIMULATION] sublist3r -d {domain}\n[-] Enumerating subdomains: www.{domain}, blog.{domain}, shop.{domain}",
                "error": "",
                "timestamp": datetime.now().isoformat()
            }
        
        result = tool_executor.execute(f"sublist3r -d {domain}", tool_name="sublist3r")
        return {
            "tool": "sublist3r",
            "target": domain,
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "error": result.get("error",""),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_sublist3r")
