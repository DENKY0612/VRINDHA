"""
Wireshark Tool Guidance per blueprint - already covered but adding module
Wireshark is GUI, we provide tshark (CLI version) wrapper for automation
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_wireshark(interface: str = "eth0") -> dict:
    try:
        if shutil.which("tshark"):
            result = tool_executor.execute(f"tshark -i {interface} -c 20", tool_name="tshark")
            return {
                "tool": "wireshark (tshark)",
                "status": result.get("status"),
                "data": result.get("output","")[:5000],
                "interface": interface,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "tool": "wireshark",
                "status": "guidance",
                "data": f"Wireshark is a GUI tool. For CLI automation use tshark. Suggested: tshark -i {interface} -c 50 -w capture.pcap. Then analyze with: tshark -r capture.pcap",
                "guidance": ["Open wireshark GUI", "Select interface", "Start capture", "Apply filters like http, dns"],
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_wireshark")

def suggest_wireshark_workflow(target: str = "") -> dict:
    return {
        "tool": "wireshark",
        "workflow": [
            f"1. Start capture: wireshark -i eth0 or tshark -i {target or 'eth0'} -c 100",
            "2. Apply filter: http or dns or ip.addr==<target>",
            "3. Analyze packets for suspicious traffic",
            "4. Export to pcap for SIEM"
        ],
        "integration": "Use with Threat Detection Engine to analyze outputs per blueprint"
    }
