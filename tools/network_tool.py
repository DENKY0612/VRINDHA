"""
Network Tools - netstat, ss, ip, etc per blueprint
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_netstat() -> dict:
    try:
        tool = "netstat" if shutil.which("netstat") else "ss" if shutil.which("ss") else None
        if not tool:
            return {"status": "simulated", "data": "[SIMULATION] netstat -tuln\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\ntcp 0 0 127.0.0.1:8000 0.0.0.0:* LISTEN"}
        cmd = "netstat -tuln" if tool == "netstat" else "ss -tuln"
        result = tool_executor.execute(cmd, tool_name=tool)
        return {"tool": tool, "status": result.get("status"), "data": result.get("output","")[:5000], "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_netstat")

def run_netdiscover(range_ip: str = "192.168.1.0/24") -> dict:
    try:
        if not shutil.which("netdiscover"):
            return {"tool": "netdiscover", "status": "simulated", "data": f"[SIMULATION] netdiscover -r {range_ip}\n192.168.1.1  AA:BB:CC:DD:EE:FF  Router\n192.168.1.10  11:22:33:44:55:66  Host"}
        result = tool_executor.execute(f"netdiscover -r {range_ip} -P", tool_name="netdiscover")
        return {"tool": "netdiscover", "status": result.get("status"), "data": result.get("output","")[:5000], "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_netdiscover")
