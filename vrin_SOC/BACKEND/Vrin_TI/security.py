"""Authentication, replay protection, rate limiting and SSRF controls."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from threading import Lock
from typing import Deque, Dict, Iterable, Optional, Tuple
from urllib.parse import urljoin, urlsplit
import hmac
import socket
import time

from .models import IntelligenceEvent


class SecurityError(ValueError):
    pass


BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal"}


def _blocked_address(value: str) -> bool:
    address = ip_address(value)
    return bool(
        address.is_private or address.is_loopback or address.is_link_local or
        address.is_multicast or address.is_reserved or address.is_unspecified
    )


def validate_external_url(url: str, *, allowed_hosts: Optional[Iterable[str]] = None, allow_http: bool = False) -> Tuple[str, Tuple[str, ...]]:
    """Validate an operator-configured external endpoint before every request.

    All resolved addresses are checked. Redirect targets must be run through
    this function again. User-controlled API calls never accept feed URLs.
    """
    if not isinstance(url, str) or len(url) > 2048:
        raise SecurityError("invalid URL length")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SecurityError("malformed URL") from exc
    schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme.lower() not in schemes:
        raise SecurityError("external URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise SecurityError("URL credentials are forbidden")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname or hostname in BLOCKED_HOSTS:
        raise SecurityError("blocked URL host")
    if allowed_hosts is not None and hostname not in {item.lower().rstrip(".") for item in allowed_hosts}:
        raise SecurityError("host is not on the connector allowlist")
    try:
        direct = ip_address(hostname)
        if _blocked_address(str(direct)):
            raise SecurityError("private, local, link-local and metadata addresses are blocked")
    except ValueError:
        pass
    try:
        results = socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SecurityError("URL host did not resolve") from exc
    addresses = tuple(sorted({item[4][0] for item in results}))
    if not addresses or any(_blocked_address(item) for item in addresses):
        raise SecurityError("URL resolves to a blocked address")
    canonical = parsed._replace(fragment="").geturl()
    return canonical, addresses


def validate_redirect(current_url: str, location: str, **kwargs) -> str:
    target = urljoin(current_url, location)
    return validate_external_url(target, **kwargs)[0]


def constant_time_token_valid(provided: str, expected: str) -> bool:
    return bool(expected and provided and hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")))


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = max(1, limit)
        self.window = max(1, window_seconds)
        self._requests: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._requests[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


@dataclass
class ReplayGuard:
    window_seconds: int = 300

    def validate(self, event: IntelligenceEvent, exists) -> None:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        skew = abs((datetime.now(timezone.utc) - timestamp).total_seconds())
        if skew > self.window_seconds:
            raise SecurityError("event timestamp is outside the replay window")
        if exists(str(event.event_id)):
            raise SecurityError("event_id was already processed")


def validate_local_file(path: str | Path, allowed_roots: Iterable[str | Path], maximum_bytes: int = 100_000_000) -> Path:
    candidate = Path(path).expanduser().resolve(strict=True)
    if not candidate.is_file() or candidate.is_symlink():
        raise SecurityError("only regular, non-symlink files are accepted")
    roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    if not any(candidate == root or root in candidate.parents for root in roots):
        raise SecurityError("file is outside configured scan roots")
    if candidate.stat().st_size > maximum_bytes:
        raise SecurityError("file exceeds scan size limit")
    return candidate


def redact_secret(value: str) -> str:
    if not value:
        return ""
    return "***" + value[-4:] if len(value) > 4 else "***"
