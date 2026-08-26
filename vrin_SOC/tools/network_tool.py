"""Local network helpers: listeners and optional netdiscover."""
from datetime import datetime
import shutil

from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.local_sensors import local_listeners
from vrin_SOC.core.tool_executor import tool_executor


def run_netstat() -> dict:
    try:
        listeners = local_listeners()
        return {
            "tool": "ss" if shutil.which("ss") else "proc",
            "status": listeners.get("status"),
            "engine": listeners.get("engine"),
            "data": listeners.get("result", ""),
            "result": listeners.get("result", ""),
            "listeners": listeners.get("listeners", []),
            "timestamp": listeners.get("timestamp", datetime.now().isoformat()),
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_netstat")


def run_netdiscover(range_ip: str = "192.168.1.0/24") -> dict:
    try:
        if shutil.which("netdiscover"):
            result = tool_executor.execute(["netdiscover", "-r", range_ip, "-P"], tool_name="netdiscover", timeout=20)
            return {
                "tool": "netdiscover",
                "status": result.get("status"),
                "data": result.get("output", "")[:5000],
                "result": result.get("output", "")[:5000],
                "timestamp": datetime.now().isoformat(),
            }
        listeners = local_listeners()
        return {
            "tool": "local-sockets",
            "status": listeners.get("status"),
            "data": listeners.get("result", ""),
            "result": listeners.get("result", ""),
            "note": "netdiscover not installed; showing local listeners",
            "timestamp": listeners.get("timestamp", datetime.now().isoformat()),
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_netdiscover")
