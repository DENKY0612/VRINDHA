"""
Network Recon Module (Red Team Controlled) per START UP.pdf
Tools: nmap, netdiscover
Responsibilities: Discover live hosts, scan open ports, identify services
Rules: Only scan authorized targets, avoid aggressive scans unless approved
Output: IP list, open ports, service versions, risk insights
"""
from vrin_SOC.tools.nmap_tool import run_nmap
from vrin_SOC.tools.network_tool import run_netdiscover
from vrin_SOC.core.error_handler import ErrorHandler
from datetime import datetime

class NetworkRecon:
    def scan(self, target: str = "192.168.1.0/24", aggressive: bool = False) -> dict:
        try:
            if aggressive:
                return {
                    "status": "requires_confirmation",
                    "message": "Aggressive scan requires explicit user approval per Red Team controlled rules. Do you want to proceed? (yes/no)",
                    "target": target,
                    "proposed": "nmap -A (aggressive)"
                }
            
            # Default safe scan
            nmap_result = run_nmap(target)
            netdiscover_result = run_netdiscover(target)
            
            return {
                "type": "network_recon",
                "target": target,
                "live_hosts": netdiscover_result.get("data",""),
                "open_ports": nmap_result.get("result",""),
                "services": "Parsed from nmap -sV output",
                "risk_insights": "Open ports may increase attack surface - review and close unnecessary ports",
                "timestamp": datetime.now().isoformat(),
                "status": "success"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "NetworkRecon.scan")

network_recon = NetworkRecon()
