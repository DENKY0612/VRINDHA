"""
Recon Agent - Per MASTER BLUEPRINT and 30-Day Plan
Tools: nmap, netdiscover, amass, sublist3r, whois, gobuster, dirb, tcpdump
Flow: Validate target, ask user confirmation (handled by Brain), run scan, return structured result
Do NOT auto-execute without approval - Brain handles that
"""
from typing import Dict
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from tools.nmap_tool import run_nmap
from tools.network_tool import run_netdiscover
from tools.whois_tool import run_whois
from tools.amass_tool import run_amass
from tools.sublist3r_tool import run_sublist3r
from tools.gobuster_tool import run_gobuster
from core.error_handler import ErrorHandler
from datetime import datetime

class ReconAgent:
    def __init__(self):
        self.name = "ReconAgent"
    
    def run(self, target: str = "127.0.0.1", tool: str = "nmap") -> Dict:
        """Main run method per Day 5-11 plan - returns structured JSON"""
        try:
            if not target:
                target = "127.0.0.1"
            
            # Route by tool choice
            if tool == "netdiscover":
                result = run_netdiscover(target)
            elif tool == "whois":
                result = run_whois(target)
            elif tool == "amass":
                result = run_amass(target)
            elif tool == "sublist3r":
                result = run_sublist3r(target)
            elif tool == "gobuster":
                result = run_gobuster(target)
            else:  # default nmap per Day 10
                result = run_nmap(target)
            
            # Better output format per Day 11
            return {
                "type": "network_scan",
                "agent": self.name,
                "target": target,
                "tool_used": tool,
                "result": result.get("result") or result.get("data") or str(result),
                "status": result.get("status","success"),
                "timestamp": datetime.now().isoformat(),
                "raw": result
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "ReconAgent.run")
            return {
                "type": "network_scan",
                "agent": self.name,
                "target": target,
                "result": "dummy result (error fallback)",
                "status": "error",
                "error": str(e)
            }
    
    def run_dummy(self) -> Dict:
        """Dummy version per Day 5"""
        return {
            "type": "network_scan",
            "data": "dummy result",
            "agent": self.name,
            "status": "success"
        }

# Global instance
recon_agent = ReconAgent()
