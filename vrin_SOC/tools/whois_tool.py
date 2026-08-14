"""
Whois Tool - Per DAY 12 Blueprint
Function: run_whois(domain) using subprocess whois
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_whois(domain: str) -> dict:
    try:
        if not domain:
            domain = "google.com"
        
        if not shutil.which("whois"):
            return {
                "type": "whois",
                "target": domain,
                "status": "simulated",
                "result": f"[SIMULATION] whois {domain}\nDomain: {domain}\nRegistrar: Example Registrar\nCreation Date: 1997-09-15\nName Servers: ns1.{domain} ns2.{domain}",
                "tool": "whois",
                "timestamp": datetime.now().isoformat()
            }
        
        result = tool_executor.execute(f"whois {domain}", tool_name="whois")
        return {
            "type": "whois",
            "target": domain,
            "status": result.get("status"),
            "result": result.get("output","")[:5000],
            "tool": "whois",
            "timestamp": datetime.now().isoformat(),
            "error": result.get("error","")
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_whois")
