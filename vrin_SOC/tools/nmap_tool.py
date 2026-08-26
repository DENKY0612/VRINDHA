"""Nmap wrapper with a Python TCP-connect fallback."""
from datetime import datetime
import shutil

from core.error_handler import ErrorHandler
from core.local_sensors import parse_nmap_table, tcp_connect_scan
from core.tool_executor import tool_executor


def run_nmap(target: str = "127.0.0.1") -> dict:
    try:
        target = target or "127.0.0.1"
        if shutil.which("nmap"):
            result = tool_executor.execute(
                ["nmap", "-sT", "-T4", "--top-ports", "50", "-Pn", target],
                tool_name="nmap",
                timeout=45,
            )
            findings = parse_nmap_table(result.get("output", ""))
            if result.get("status") == "success" or findings:
                return {
                    "type": "network_scan",
                    "target": target,
                    "status": "success" if result.get("status") == "success" else result.get("status"),
                    "engine": "nmap",
                    "result": (result.get("output") or "")[:5000],
                    "findings": findings,
                    "tool": "nmap",
                    "timestamp": datetime.now().isoformat(),
                    "error": result.get("error", ""),
                }
        scan = tcp_connect_scan(target)
        return {
            "type": "network_scan",
            "target": scan.get("target", target),
            "status": scan.get("status", "success"),
            "engine": scan.get("engine"),
            "result": scan.get("result", ""),
            "findings": scan.get("open_ports", []),
            "tool": "python-tcp",
            "timestamp": scan.get("timestamp", datetime.now().isoformat()),
            "note": scan.get("note", "nmap not installed; used Python TCP connect scan"),
            "error": scan.get("error", ""),
        }
    except ValueError as exc:
        return {"type": "network_scan", "target": target, "status": "error", "result": str(exc), "findings": [], "tool": "nmap"}
    except Exception as exc:
        return ErrorHandler.handle_exception(exc, "run_nmap")


def run_nmap_detailed(target: str):
    return run_nmap(target)


if __name__ == "__main__":
    print(run_nmap("127.0.0.1"))
