"""tcpdump wrapper with a local-listener fallback."""
from datetime import datetime
import shutil

from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.local_sensors import local_listeners
from vrin_SOC.core.tool_executor import tool_executor, validate_interface


def run_tcpdump(interface: str = "eth0") -> dict:
    try:
        interface = interface or "lo"
        valid, interface_or_error = validate_interface(interface)
        if not valid:
            return {"tool": "tcpdump", "status": "error", "error": interface_or_error,
                    "timestamp": datetime.now().isoformat()}
        interface = interface_or_error
        if shutil.which("tcpdump"):
            result = tool_executor.execute(
                ["tcpdump", "-i", interface, "-c", "50", "-nn"],
                tool_name="tcpdump",
                timeout=20,
            )
            return {
                "tool": "tcpdump",
                "interface": interface,
                "status": result.get("status"),
                "engine": "tcpdump",
                "data": result.get("output", "")[:5000],
                "result": result.get("output", "")[:5000],
                "error": result.get("error", ""),
                "timestamp": datetime.now().isoformat(),
                "safety": "Limited to 50 packets",
            }
        listeners = local_listeners()
        return {
            "tool": "local-sockets",
            "interface": interface,
            "status": listeners.get("status"),
            "engine": listeners.get("engine"),
            "data": listeners.get("result", ""),
            "result": listeners.get("result", ""),
            "listeners": listeners.get("listeners", []),
            "error": "",
            "timestamp": listeners.get("timestamp", datetime.now().isoformat()),
            "safety": "tcpdump not installed; listed local listening sockets instead of capturing packets",
        }
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_tcpdump")
