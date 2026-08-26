"""
Snort Tool - IDS per blueprint (already covered but module for verification)
"""
from vrin_SOC.core.tool_executor import tool_executor
from vrin_SOC.core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_snort(interface: str = "eth0") -> dict:
    try:
        if not shutil.which("snort"):
            # A missing IDS must not manufacture an incident. Keep the result
            # explicit so callers can show a simulation/degraded state without
            # persisting a false alert or blocking an IP.
            return {
                "tool": "snort",
                "status": "simulated",
                "simulated": True,
                "data": "[SIMULATION] Snort is not installed; no live IDS alerts were collected.",
                "alerts": [],
                "timestamp": datetime.now().isoformat(),
                "note": "Install Snort to enable live IDS monitoring; this fallback is observation-only.",
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
