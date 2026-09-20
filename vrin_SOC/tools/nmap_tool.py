"""Nmap wrapper supporting all major scan types and options.

Supports arbitrary nmap flags passed as a list:
    run_nmap("192.168.1.1", flags=["-sS", "-sV", "-T4"])
    
Or use convenience scan types:
    run_nmap("192.168.1.1", scan_type="syn")
    run_nmap("192.168.1.1", scan_type="aggressive")
"""
from datetime import datetime
import shutil

from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.local_sensors import parse_nmap_table, tcp_connect_scan
from vrin_SOC.core.tool_executor import tool_executor


# Preset scan types mapping to nmap flags
SCAN_PRESETS = {
    # Scan Techniques
    "syn": ["-sS", "-T4", "-Pn"],
    "tcp": ["-sT", "-T4", "-Pn"],
    "udp": ["-sU", "-T4", "-Pn"],
    "ack": ["-sA", "-T4", "-Pn"],
    "null": ["-sN", "-T4", "-Pn"],
    "fin": ["-sF", "-T4", "-Pn"],
    "xmas": ["-sX", "-T4", "-Pn"],
    # Host Discovery
    "ping": ["-sn"],
    "no-ping": ["-Pn", "-T4","--top-ports","50"],
    "syn-ping": ["-PS", "-T4"],
    "ack-ping": ["-PA", "-T4"],
    "udp-ping": ["-PU", "-T4"],
    "arp-ping": ["-PR", "-T4"],
    # Service/OS Detection
    "version": ["-sV", "-T4", "-Pn"],
    "os-detect": ["-O", "-T4", "-Pn"],
    "aggressive": ["-A", "-T4", "-Pn"],
    # Timing
    "paranoid": ["-sT", "-T0", "-Pn"],
    "sneaky": ["-sT", "-T1", "-Pn"],
    "polite": ["-sT", "-T2", "-Pn"],
    "normal": ["-sT", "-T3", "-Pn"],
    "insane": ["-sT", "-T5", "-Pn"],
    # NSE
    "scripts": ["-sC", "-T4", "-Pn"],
    "vuln": ["--script=vuln", "-T4", "-Pn"],
    # Port scans
    "fast": ["-F", "-T4", "-Pn"],
    "all-ports": ["-p-", "-T4", "-Pn"],
    # Evasion
    "fragment": ["-f", "-T4", "-Pn"],
    # Default
    "default": ["-sT", "-T4", "--top-ports", "50", "-Pn"],
}


def run_nmap(target: str = "127.0.0.1", flags: list = None, scan_type: str = None, timeout: int = 60) -> dict:
    """Run nmap with optional flags or preset scan type.
    
    Args:
        target: IP/hostname to scan
        flags: List of nmap flags, e.g. ["-sS", "-sV", "-T4"]
        scan_type: Preset name like "syn", "aggressive", "udp"
        timeout: Timeout in seconds
    """
    try:
        target = target or "127.0.0.1"
        
        # Build command
        if flags:
            cmd = ["nmap"] + flags + [target]
        elif scan_type and scan_type in SCAN_PRESETS:
            cmd = ["nmap"] + SCAN_PRESETS[scan_type] + [target]
        else:
            cmd = ["nmap", "-sT", "-T4", "--top-ports", "50", "-Pn", target]
        
        if shutil.which("nmap"):
            result = tool_executor.execute(
                cmd,
                tool_name="nmap",
                timeout=timeout,
            )
            findings = parse_nmap_table(result.get("output", ""))
            
            # Extract scan type from command for display
            scan_desc = _describe_scan(cmd)
            
            if result.get("status") == "success" or findings:
                return {
                    "type": "network_scan",
                    "target": target,
                    "scan_type": scan_desc,
                    "status": "success" if result.get("status") == "success" else result.get("status"),
                    "engine": "nmap",
                    "result": (result.get("output") or "")[:5000],
                    "findings": findings,
                    "tool": "nmap",
                    "timestamp": datetime.now().isoformat(),
                    "error": result.get("error", ""),
                }
        # Fallback to TCP connect scan
        scan = tcp_connect_scan(target)
        return {
            "type": "network_scan",
            "target": scan.get("target", target),
            "scan_type": "tcp-fallback",
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


def _describe_scan(cmd: list) -> str:
    """Generate human-readable scan description from nmap command."""
    flags = [c for c in cmd if c.startswith("-")]
    scan_type_map = {
        "-sS": "SYN Stealth", "-sT": "TCP Connect", "-sU": "UDP",
        "-sA": "ACK", "-sN": "Null", "-sX": "Xmas", "-sF": "FIN",
        "-sV": "Version Detect", "-O": "OS Detect", "-A": "Aggressive",
        "-sn": "Ping Scan", "-F": "Fast", "-p-": "All Ports",
        "-sC": "Scripts", "--script=vuln": "Vuln Scan",
        "-T0": "Paranoid", "-T1": "Sneaky", "-T2": "Polite",
        "-T3": "Normal", "-T4": "Aggressive", "-T5": "Insane",
        "-f": "Fragment",
    }
    parts = []
    for f in flags:
        if f in scan_type_map:
            parts.append(scan_type_map[f])
    return " + ".join(parts) if parts else "Standard"


def run_nmap_detailed(target: str):
    return run_nmap(target, scan_type="aggressive")


if __name__ == "__main__":
    print(run_nmap("127.0.0.1"))
