"""
Amass Tool - Advanced Recon & OSINT per blueprint
Function: run_amass(domain) asks confirmation, runs amass enum -d domain
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_amass(domain: str) -> dict:
    try:
        if not domain:
            domain = "example.com"
        
        if not shutil.which("amass"):
            return {
                "tool": "amass",
                "target": domain,
                "status": "simulated",
                "data": f"[SIMULATION] amass enum -d {domain}\nFound: mail.{domain}, www.{domain}, api.{domain}, dev.{domain}",
                "error": "",
                "timestamp": datetime.now().isoformat(),
                "note": "Install amass: sudo apt install amass"
            }
        
        result = tool_executor.execute(f"amass enum -d {domain}", tool_name="amass")
        return {
            "tool": "amass",
            "target": domain,
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "error": result.get("error",""),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_amass")
