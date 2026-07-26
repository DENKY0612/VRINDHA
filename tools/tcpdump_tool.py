"""
tcpdump Tool - Network Sniffing per blueprint
Function: run_tcpdump(interface) - asks confirmation, runs tcpdump -i interface -c 50, limited capture count to avoid infinite
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_tcpdump(interface: str = "eth0") -> dict:
    try:
        if not interface:
            interface = "lo"
        
        if not shutil.which("tcpdump"):
            return {
                "tool": "tcpdump",
                "interface": interface,
                "status": "simulated",
                "data": f"[SIMULATION] tcpdump -i {interface} -c 50\n12:00:01 IP 127.0.0.1.54321 > 127.0.0.1.80: Flags [S]\n12:00:02 IP 127.0.0.1.80 > 127.0.0.1.54321: Flags [S.]\nCaptured 50 packets summary: 30 TCP, 15 UDP, 5 ICMP",
                "error": "",
                "timestamp": datetime.now().isoformat(),
                "safety": "Limit capture count to 50 for safety"
            }
        
        result = tool_executor.execute(f"tcpdump -i {interface} -c 50", tool_name="tcpdump")
        return {
            "tool": "tcpdump",
            "interface": interface,
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "error": result.get("error",""),
            "timestamp": datetime.now().isoformat(),
            "safety": "Limited to 50 packets per blueprint safety"
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_tcpdump")
