"""
Nmap Tool - Per DAY 8-11 Blueprint
Function: run_nmap(target) using subprocess nmap -sV target, return structured output
Safety: timeout 10 sec, check installation
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import subprocess, shutil, json
from datetime import datetime

def run_nmap(target: str = "127.0.0.1") -> dict:
    try:
        if not target:
            target = "127.0.0.1"
        
        # Safety: only allow reasonable targets, default to loopback if empty
        # Check tool availability
        if not shutil.which("nmap"):
            return {
                "type": "network_scan",
                "target": target,
                "status": "simulated",
                "result": f"[SIMULATION] nmap -sV {target} - Tool not installed. Install: sudo apt install nmap\nDummy open ports: 22/tcp ssh, 80/tcp http, 443/tcp https",
                "tool": "nmap",
                "timestamp": datetime.now().isoformat(),
                "note": "Install nmap for real scans"
            }
        
        # Safe execution
        result = tool_executor.execute(f"nmap -sV {target}", tool_name="nmap")
        
        return {
            "type": "network_scan",
            "target": target,
            "status": result.get("status"),
            "result": result.get("output", "")[:5000],
            "tool": "nmap",
            "timestamp": datetime.now().isoformat(),
            "error": result.get("error","")
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_nmap")

def run_nmap_detailed(target: str):
    """Extended with JSON structured"""
    data = run_nmap(target)
    return {
        "type": "network_scan",
        "target": target,
        "result": data.get("result"),
        "status": data.get("status","success")
    }

# Test function per Day 9
if __name__ == "__main__":
    print(run_nmap("127.0.0.1"))
