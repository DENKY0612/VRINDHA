"""Feed adapter primitives and bounded safe HTTP retrieval."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
import json

from ..security import validate_external_url, validate_redirect


class FeedError(RuntimeError):
    pass


@dataclass
class CollectedItem:
    kind: str  # indicator | stix | vulnerability | event
    payload: Dict[str, Any]


@dataclass
class CollectionBatch:
    items: List[CollectedItem] = field(default_factory=list)
    cursor: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


async def fetch_json(url: str, *, allowed_hosts: Sequence[str], timeout: int = 30,
                     headers: Optional[Dict[str, str]] = None, max_bytes: int = 10_000_000,
                     max_redirects: int = 3) -> Any:
    try:
        import httpx
    except ImportError as exc:
        raise FeedError("httpx is required for HTTP feeds") from exc
    current = validate_external_url(url, allowed_hosts=allowed_hosts)[0]
    request_headers = {"Accept": "application/json", "User-Agent": "Vrindha-TI/1.0", **(headers or {})}
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), verify=True, follow_redirects=False, headers=request_headers) as client:
        for _ in range(max_redirects + 1):
            # Resolve and validate again immediately before every request. This
            # also catches DNS changes between pages/redirects.
            validate_external_url(current, allowed_hosts=allowed_hosts)
            async with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise FeedError("redirect did not include Location")
                    current = validate_redirect(current, location, allowed_hosts=allowed_hosts)
                    continue
                if response.status_code >= 400:
                    raise FeedError(f"feed returned HTTP {response.status_code}")
                length = response.headers.get("content-length")
                if length and length.isdigit() and int(length) > max_bytes:
                    raise FeedError("feed response exceeds size limit")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise FeedError("feed response exceeds size limit")
            try:
                return json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise FeedError("feed returned malformed JSON") from exc
    raise FeedError("too many redirects")


class FeedCollector(ABC):
    name: str
    reliability: float

    def __init__(self, *, timeout: int = 30, reliability: float = 0.8):
        self.timeout = timeout
        self.reliability = reliability

    @abstractmethod
    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch: ...
