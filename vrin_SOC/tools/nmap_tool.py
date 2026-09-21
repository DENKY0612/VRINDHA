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
    import time
    start_time = time.time()
    
    try:
        target = target or "127.0.0.1"
        original_target = target
        
        # Detect IPv6 and add -6 flag if needed
        is_ipv6 = ":" in target and not target.startswith("[")
        if is_ipv6:
            # Strip brackets if present for nmap target
            target = target.strip("[]")
        
        # Build command
        if flags:
            cmd = ["nmap"] + flags + [target]
            # Auto-add -6 for IPv6 if not already in flags
            if is_ipv6 and "-6" not in flags:
                cmd.insert(1, "-6")
        elif scan_type and scan_type in SCAN_PRESETS:
            cmd = ["nmap"] + SCAN_PRESETS[scan_type] + [target]
            if is_ipv6 and "-6" not in SCAN_PRESETS[scan_type]:
                cmd.insert(1, "-6")
        else:
            cmd = ["nmap", "-sT", "-T4", "--top-ports", "50", "-Pn", target]
            if is_ipv6:
                cmd.insert(1, "-6")
        
        scan_desc = _describe_scan(cmd)
        ports_scanned = _estimate_ports_scanned(cmd)
        
        if shutil.which("nmap"):
            result = tool_executor.execute(
                cmd,
                tool_name="nmap",
                timeout=timeout,
            )
            findings = parse_nmap_table(result.get("output", ""))
            
            # Extract richer metadata from raw output
            os_guess = _extract_os_guess(result.get("output", ""))
            reverse_dns = _extract_reverse_dns(result.get("output", ""))
            scan_duration = _extract_scan_duration(result.get("output", ""))
            open_count, filtered_count, closed_count = _count_port_states(result.get("output", ""), findings)
            
            elapsed = round(time.time() - start_time, 2)
            
            if result.get("status") == "success" or findings:
                return {
                    "type": "network_scan",
                    "target": target,
                    "target_ip_type": "IPv6" if is_ipv6 else "IPv4",
                    "target_reverse_dns": reverse_dns,
                    "scan_type": scan_desc,
                    "status": "success" if result.get("status") == "success" else result.get("status"),
                    "engine": "nmap",
                    "result": (result.get("output") or "")[:5000],
                    "findings": findings,
                    "tool": "nmap",
                    "timestamp": datetime.now().isoformat(),
                    "scan_duration_seconds": scan_duration or elapsed,
                    "ports_scanned": ports_scanned,
                    "open_ports": open_count,
                    "filtered_ports": filtered_count,
                    "closed_ports": closed_count,
                    "total_ports": len(findings),
                    "os_guess": os_guess,
                    "recommendations": _generate_nmap_recommendations(findings, os_guess),
                    "error": result.get("error", ""),
                }
        # Fallback to TCP connect scan
        scan = tcp_connect_scan(target)
        elapsed = round(time.time() - start_time, 2)
        findings = scan.get("open_ports", [])
        
        # Enrich fallback scan result
        os_guess = None
        reverse_dns = None
        try:
            import socket
            reverse_dns = socket.gethostbyaddr(target)[0]
        except Exception:
            pass
            
        return {
            "type": "network_scan",
            "target": scan.get("target", target),
            "target_ip_type": "IPv6" if is_ipv6 else "IPv4",
            "target_reverse_dns": reverse_dns,
            "scan_type": "tcp-fallback",
            "status": scan.get("status", "success"),
            "engine": scan.get("engine"),
            "result": scan.get("result", ""),
            "findings": findings,
            "tool": "python-tcp",
            "timestamp": scan.get("timestamp", datetime.now().isoformat()),
            "note": scan.get("note", "nmap not installed; used Python TCP connect scan"),
            "error": scan.get("error", ""),
            "scan_duration_seconds": elapsed,
            "ports_scanned": len(scan.get("open_ports", [])),
            "open_ports": len(findings),
            "filtered_ports": 0,
            "closed_ports": 0,
            "total_ports": len(findings),
            "os_guess": None,
            "recommendations": _generate_nmap_recommendations(findings, None),
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


def _estimate_ports_scanned(cmd: list) -> int:
    """Estimate the number of ports scanned from command flags."""
    if "-p-" in cmd:
        return 65535
    for i, flag in enumerate(cmd):
        if flag == "-p" and i + 1 < len(cmd):
            return 65535  # -p- means all ports
    for i, flag in enumerate(cmd):
        if flag == "--top-ports" and i + 1 < len(cmd):
            try:
                return int(cmd[i + 1])
            except ValueError:
                pass
    if "-F" in cmd:
        return 100
    return 1000  # default


def _extract_os_guess(output: str) -> str:
    """Extract OS guess from nmap output."""
    for line in output.splitlines():
        line_lower = line.lower()
        if "os:" in line_lower or "running:" in line_lower:
            # Clean up the line
            parts = line.strip()
            if len(parts) > 200:
                parts = parts[:200]
            return parts
    return None


def _extract_reverse_dns(output: str) -> str:
    """Extract reverse DNS from nmap output."""
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            # Format: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
            parts = line.split("for")[1].strip()
            if "(" in parts:
                hostname = parts.split("(")[0].strip()
                return hostname
    return None


def _extract_scan_duration(output: str) -> float:
    """Extract scan duration from nmap output (seconds)."""
    import re
    for line in output.splitlines():
        match = re.search(r"scanned.*in\s+([\d.]+)\s+seconds", line, re.IGNORECASE)
        if match:
            return round(float(match.group(1)), 2)
    return None


def _count_port_states(output: str, findings: list) -> tuple:
    """Count port states from findings and output."""
    open_count = sum(1 for f in findings if f.get("state") == "open")
    filtered_count = sum(1 for f in findings if f.get("state") == "filtered")
    closed_count = sum(1 for f in findings if f.get("state") == "closed")
    return open_count, filtered_count, closed_count


def _generate_nmap_recommendations(findings: list, os_guess: str) -> list:
    """Generate security recommendations based on scan findings."""
    recs = []
    
    open_ports = [f for f in findings if f.get("state") == "open"]
    
    if not open_ports:
        recs.append("✅ Target appears well-hardened - no open ports detected")
        return recs
    
    # Check for risky ports
    risky_services = {
        23: "Telnet (plaintext protocol) - disable and use SSH",
        21: "FTP (plaintext protocol) - consider SFTP/SCP",
        139: "NetBIOS - disable if not needed",
        445: "SMB - ensure patched and firewall-restricted",
        3389: "RDP - restrict access and use NLA",
        5900: "VNC - ensure encrypted tunnel used",
        6379: "Redis - should not be publicly accessible",
        3306: "MySQL - restrict to internal network",
        5432: "PostgreSQL - restrict to internal network",
        27017: "MongoDB - restrict to internal network",
        9200: "Elasticsearch - restrict access",
    }
    
    high_risk_found = False
    for f in open_ports:
        port = f.get("port", 0)
        if port in risky_services:
            recs.append(f"⚠️  Port {port}: {risky_services[port]}")
            high_risk_found = True
    
    if high_risk_found:
        recs.append("🔒 Consider implementing network segmentation and firewall rules")
    
    if os_guess:
        recs.append(f"🔍 OS detected - verify latest security patches applied")
    
    # General recommendations
    if len(open_ports) > 10:
        recs.append("📊 Many open ports detected - review attack surface")
    
    if not high_risk_found and len(open_ports) <= 3:
        recs.append("✅ Minimal attack surface - only standard services detected")
    
    return recs


def run_nmap_detailed(target: str):
    return run_nmap(target, scan_type="aggressive")


if __name__ == "__main__":
    print(run_nmap("127.0.0.1"))
