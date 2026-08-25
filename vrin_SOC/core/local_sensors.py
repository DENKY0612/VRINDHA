"""Python-native defensive sensors used when Kali binaries are missing.

These are lab-safe equivalents of common recon/defense tools: TCP connect
scan, WHOIS, HTTP path probe, DNS prefix lookup, and local listener listing.
Callers must already have passed authorization and (for Red Team) confirmation.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import ipaddress
import socket
import shutil
import subprocess

COMMON_PORTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}

COMMON_PATHS = (
    "/",
    "/admin",
    "/login",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/api",
    "/health",
    "/status",
    "/dashboard/",
    "/docs",
    "/server-status",
    "/config",
    "/backup",
)

DNS_PREFIXES = ("www", "mail", "api", "dev", "staging", "vpn", "ns1", "ns2", "cdn", "app")


def utcstamp() -> str:
    return datetime.now().isoformat()


def single_host(target: str) -> str:
    """Return a single host from a target, rejecting wide CIDR ranges."""
    value = (target or "").strip()
    if not value:
        return "127.0.0.1"
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value.split("/", 1)[0]
        if network.num_addresses > 1:
            raise ValueError(
                f"{value} is a range ({network.num_addresses} addresses). "
                "Specify a single IP when Kali nmap is not installed."
            )
        return str(network.network_address)
    return value


def _probe_port(host: str, port: int, timeout: float) -> Optional[Tuple[int, str]]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, COMMON_PORTS.get(port, "unknown")
    except OSError:
        return None


def tcp_connect_scan(target: str, ports: Optional[Iterable[int]] = None, timeout: float = 0.35) -> Dict:
    host = single_host(target)
    chosen = list(ports) if ports is not None else list(COMMON_PORTS)
    open_ports: List[Dict] = []
    with ThreadPoolExecutor(max_workers=min(16, len(chosen) or 1)) as pool:
        futures = [pool.submit(_probe_port, host, port, timeout) for port in chosen]
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                open_ports.append({"port": hit[0], "state": "open", "service": hit[1]})
    open_ports.sort(key=lambda item: item["port"])
    lines = [f"{item['port']}/tcp open {item['service']}" for item in open_ports] or ["No open common ports detected"]
    return {
        "status": "success",
        "engine": "python-tcp",
        "target": host,
        "open_ports": open_ports,
        "result": "PORT      STATE SERVICE\n" + "\n".join(f"{item['port']:<9} open  {item['service']}" for item in open_ports)
        if open_ports
        else f"No open common ports on {host}",
        "summary": f"{len(open_ports)} open port(s) on {host}",
        "timestamp": utcstamp(),
        "note": "TCP connect scan of common ports (nmap not required)",
    }


def parse_nmap_table(output: str) -> List[Dict]:
    findings: List[Dict] = []
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and "/tcp" in parts[0] and parts[1] in {"open", "filtered", "closed"}:
            port = int(parts[0].split("/", 1)[0])
            findings.append({"port": port, "state": parts[1], "service": parts[2]})
    return findings


def _whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query.strip() + "\r\n").encode("ascii", "ignore"))
        chunks: List[bytes] = []
        while True:
            piece = sock.recv(4096)
            if not piece:
                break
            chunks.append(piece)
            if sum(len(item) for item in chunks) > 200_000:
                break
    return b"".join(chunks).decode("utf-8", "replace")


def whois_lookup(target: str) -> Dict:
    host = (target or "").strip().rstrip(".")
    if not host:
        raise ValueError("WHOIS target is empty")
    try:
        referral = _whois_query("whois.iana.org", host)
    except OSError as exc:
        return {
            "status": "error",
            "engine": "python-whois",
            "target": host,
            "result": "",
            "error": f"Could not reach whois.iana.org: {exc}",
            "timestamp": utcstamp(),
        }
    server = ""
    for line in referral.splitlines():
        if line.lower().startswith("whois:"):
            server = line.split(":", 1)[1].strip()
            break
    body = referral
    if server and server not in {"whois.iana.org", ""}:
        try:
            body = _whois_query(server, host)
        except OSError:
            body = referral
    return {
        "status": "success",
        "engine": "python-whois",
        "target": host,
        "registrar_whois": server or "whois.iana.org",
        "result": body[:8000],
        "timestamp": utcstamp(),
    }


def http_probe(target: str, paths: Iterable[str] = COMMON_PATHS, timeout: float = 2.0) -> Dict:
    raw = (target or "127.0.0.1").strip()
    if not raw.startswith("http"):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    base = f"{parsed.scheme}://{parsed.netloc or parsed.path}"
    found: List[Dict] = []
    for path in paths:
        url = base.rstrip("/") + path
        try:
            request = Request(url, method="HEAD", headers={"User-Agent": "Vrindha-SOC/1.1"})
            with urlopen(request, timeout=timeout) as response:
                found.append({"path": path, "status": response.status, "url": url})
        except HTTPError as exc:
            if exc.code < 500 and exc.code != 404:
                found.append({"path": path, "status": exc.code, "url": url})
        except (URLError, TimeoutError, OSError, ValueError):
            continue
    lines = [f"{item['status']} {item['path']}" for item in found] or ["No common web paths responded"]
    return {
        "status": "success",
        "engine": "python-http",
        "target": base,
        "findings": found,
        "result": "\n".join(lines),
        "summary": f"{len(found)} path(s) responded on {base}",
        "timestamp": utcstamp(),
    }


def dns_prefixes(domain: str) -> Dict:
    host = (domain or "").strip().rstrip(".").lstrip(".")
    if not host or " " in host:
        raise ValueError("Domain is required")
    names = [host] + [f"{prefix}.{host}" for prefix in DNS_PREFIXES]
    resolved: List[Dict] = []
    for name in names:
        try:
            answers = socket.getaddrinfo(name, None)
        except socket.gaierror:
            continue
        addrs = sorted({item[4][0] for item in answers})
        if addrs:
            resolved.append({"name": name, "addresses": addrs})
    return {
        "status": "success",
        "engine": "python-dns",
        "target": host,
        "findings": resolved,
        "result": "\n".join(f"{item['name']} → {', '.join(item['addresses'])}" for item in resolved)
        or f"No common prefixes resolved for {host}",
        "timestamp": utcstamp(),
    }


def _parse_proc_net(path: str, ipv6: bool = False) -> List[Dict]:
    rows: List[Dict] = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        if state != "0A":  # TCP_LISTEN
            continue
        ip_hex, port_hex = local.split(":")
        try:
            port = int(port_hex, 16)
            if ipv6:
                address = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(ip_hex)[::-1]) if False else ip_hex
                # Keep compact: show hex-decoded IPv4-mapped when possible
                address = _decode_ipv6_hex(ip_hex)
            else:
                raw = bytes.fromhex(ip_hex)
                address = ".".join(str(b) for b in raw[::-1])
        except (ValueError, OSError):
            continue
        rows.append({"address": address, "port": port, "remote": remote, "state": "LISTEN"})
    return rows


def _decode_ipv6_hex(value: str) -> str:
    try:
        data = bytes.fromhex(value)
        # /proc/net/tcp6 stores little-endian 32-bit words
        words = [data[i : i + 4][::-1] for i in range(0, 16, 4)]
        return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    except (ValueError, OSError):
        return value


def local_listeners() -> Dict:
    listeners = _parse_proc_net("/proc/net/tcp") + _parse_proc_net("/proc/net/tcp6", ipv6=True)
    ss_output = ""
    if shutil.which("ss"):
        try:
            completed = subprocess.run(
                ["ss", "-tuln"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            ss_output = (completed.stdout or "")[:4000]
        except (OSError, subprocess.TimeoutExpired):
            ss_output = ""
    rendered = ss_output or "\n".join(f"{item['address']}:{item['port']} LISTEN" for item in listeners) or "No listeners found"
    return {
        "status": "success",
        "engine": "local-sockets",
        "listeners": listeners,
        "result": rendered,
        "summary": f"{len(listeners)} listening TCP socket(s)",
        "timestamp": utcstamp(),
    }
