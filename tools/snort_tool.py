"""
Snort Tool - IDS per blueprint (already covered but module for verification)
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_snort(interface: str = "eth0") -> dict:
    try:
        if not shutil.which("snort"):
            return {
                "tool": "snort",
                "status": "simulated",
                "data": "[SIMULATION] Snort IDS monitoring\n[**] [1:1000:1] TCP Port Scan Detected [**]\n[Priority: 2] {TCP} 192.168.1.50:1234 -> 192.168.1.1:80",
                "alerts": [{"sid": "1:1000:1", "msg": "TCP Port Scan", "severity": "Medium"}],
                "timestamp": datetime.now().isoformat()
            }
        result = tool_executor.execute(f"snort -i {interface} -c /etc/snort/snort.conf -A console -q -N -l /var/log/snort", tool_name="snort")
        return {
            "tool": "snort",
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_snort")
