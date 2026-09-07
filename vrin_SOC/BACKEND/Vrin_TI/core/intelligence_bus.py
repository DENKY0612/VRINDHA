"""Dedicated SOC↔TI Intelligence Communication Layer.

Transports are interchangeable. Redis/NATS/HTTP are opportunistic; the SQLite
local queue is always available and receives messages whenever another
transport cannot. Nothing in this module invokes a shell or response action.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import suppress
from ipaddress import ip_address
from typing import AsyncIterator, Dict, List
from urllib.parse import urlsplit
import asyncio
import logging

from ..config import TIConfig
from ..database import ThreatDatabase
from ..models import IntelligenceEvent

logger = logging.getLogger("vrindha.ti.bus")


class TransportError(RuntimeError):
    pass


class IntelligenceTransport(ABC):
    name = "abstract"

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def publish(self, event: IntelligenceEvent) -> None: ...

    @abstractmethod
    async def health(self) -> Dict[str, object]: ...


class LocalQueueTransport(IntelligenceTransport):
    name = "local_queue"

    def __init__(self, database: ThreatDatabase, direction: str = "outbound"):
        self.database = database
        self.direction = direction
        self.connected = False

    async def connect(self) -> None:
        await asyncio.to_thread(self.database.queue_depth)
        self.connected = True

    async def close(self) -> None:
        self.connected = False

    async def publish(self, event: IntelligenceEvent) -> None:
        if not self.connected:
            await self.connect()
        await asyncio.to_thread(self.database.queue_event, event, self.direction)

    async def health(self) -> Dict[str, object]:
        try:
            depth = await asyncio.to_thread(self.database.queue_depth)
            return {"name": self.name, "status": "connected", "queue_depth": depth, "durable": True}
        except Exception as exc:
            return {"name": self.name, "status": "error", "error": str(exc)[:256], "durable": True}


class RedisTransport(IntelligenceTransport):
    name = "redis"

    def __init__(self, url: str, stream: str = "vrindha:intelligence"):
        self.url = url
        self.stream = stream
        self.client = None

    async def connect(self) -> None:
        if not self.url:
            raise TransportError("Redis URL is not configured")
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError as exc:
            raise TransportError("redis package is unavailable") from exc
        self.client = redis.from_url(self.url, decode_responses=True, socket_connect_timeout=2, socket_timeout=3)
        await self.client.ping()

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()
        self.client = None

    async def publish(self, event: IntelligenceEvent) -> None:
        if not self.client:
            raise TransportError("Redis is disconnected")
        await self.client.xadd(self.stream, {"event": event.model_dump_json()}, maxlen=100_000, approximate=True)

    async def health(self) -> Dict[str, object]:
        try:
            if not self.client:
                return {"name": self.name, "status": "disconnected"}
            await self.client.ping()
            return {"name": self.name, "status": "connected", "stream": self.stream}
        except Exception as exc:
            return {"name": self.name, "status": "error", "error": str(exc)[:256]}


class NATSTransport(IntelligenceTransport):
    name = "nats"

    def __init__(self, url: str, subject: str = "vrindha.intelligence"):
        self.url = url
        self.subject = subject
        self.client = None
        self.jetstream = None

    async def connect(self) -> None:
        if not self.url:
            raise TransportError("NATS URL is not configured")
        try:
            import nats  # type: ignore
        except ImportError as exc:
            raise TransportError("nats-py package is unavailable") from exc
        self.client = await nats.connect(servers=[self.url], connect_timeout=2, max_reconnect_attempts=3, reconnect_time_wait=1)
        self.jetstream = self.client.jetstream()

    async def close(self) -> None:
        if self.client:
            await self.client.drain()
        self.client = self.jetstream = None

    async def publish(self, event: IntelligenceEvent) -> None:
        if not self.client:
            raise TransportError("NATS is disconnected")
        payload = event.model_dump_json().encode("utf-8")
        try:
            await self.jetstream.publish(self.subject, payload, timeout=3)
        except Exception:
            # Core NATS is still useful if JetStream was not provisioned. The
            # manager records that it is non-durable; SQLite retains fallback.
            await self.client.publish(self.subject, payload)
            await self.client.flush(timeout=3)

    async def health(self) -> Dict[str, object]:
        connected = bool(self.client and self.client.is_connected)
        return {"name": self.name, "status": "connected" if connected else "disconnected", "subject": self.subject}


class HTTPTransport(IntelligenceTransport):
    name = "http"

    def __init__(self, base_url: str, service_token: str):
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.client = None
        self._validate_url()

    def _validate_url(self) -> None:
        parsed = urlsplit(self.base_url)
        host = parsed.hostname or ""
        local = host in {"localhost", "127.0.0.1", "::1"}
        try:
            local = local or ip_address(host).is_loopback
        except ValueError:
            pass
        if parsed.scheme == "http" and local:
            return
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise TransportError("remote SOC transport requires HTTPS without URL credentials")

    async def connect(self) -> None:
        if not self.service_token:
            raise TransportError("service token is not configured")
        try:
            import httpx
        except ImportError as exc:
            raise TransportError("httpx package is unavailable") from exc
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=httpx.Timeout(5), verify=True, follow_redirects=False,
                                        headers={"X-Vrindha-Service-Token": self.service_token, "User-Agent": "Vrindha-TI/1.0"})
        # Do not require SOC to be online merely to instantiate. A bounded
        # health request establishes availability during manager selection.
        response = await self.client.get("/intelligence/health")
        if response.status_code >= 400:
            raise TransportError(f"SOC gateway health returned {response.status_code}")

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()
        self.client = None

    async def publish(self, event: IntelligenceEvent) -> None:
        if not self.client:
            raise TransportError("HTTP transport is disconnected")
        response = await self.client.post("/intelligence/events", json=event.model_dump(mode="json"))
        if response.status_code >= 400:
            raise TransportError(f"SOC gateway returned {response.status_code}")

    async def health(self) -> Dict[str, object]:
        if not self.client:
            return {"name": self.name, "status": "disconnected", "endpoint": self.base_url}
        try:
            response = await self.client.get("/intelligence/health")
            return {"name": self.name, "status": "connected" if response.status_code < 400 else "degraded", "endpoint": self.base_url}
        except Exception as exc:
            return {"name": self.name, "status": "error", "endpoint": self.base_url, "error": str(exc)[:256]}


class TransportManager:
    """Select the best healthy transport and always retain SQLite fallback."""

    def __init__(self, config: TIConfig, database: ThreatDatabase):
        self.config = config
        self.database = database
        self.fallback = LocalQueueTransport(database)
        self.active: IntelligenceTransport = self.fallback
        self.state = "disconnected"
        self.last_error = ""
        self._subscribers: List[asyncio.Queue[IntelligenceEvent]] = []
        self._lock = asyncio.Lock()

    def _make(self, name: str) -> IntelligenceTransport:
        if name == "redis":
            return RedisTransport(self.config.redis_url)
        if name == "nats":
            return NATSTransport(self.config.nats_url)
        if name == "http":
            return HTTPTransport(self.config.soc_url, self.config.service_token)
        return self.fallback

    def _candidates(self) -> List[IntelligenceTransport]:
        if self.config.transport != "auto":
            selected = self._make(self.config.transport)
            return [selected] if selected is self.fallback else [selected, self.fallback]
        names: List[str] = []
        if self.config.redis_url:
            names.append("redis")
        if self.config.nats_url:
            names.append("nats")
        if self.config.service_token and self.config.soc_url:
            names.append("http")
        candidates: List[IntelligenceTransport] = []
        for name in names:
            try:
                candidates.append(self._make(name))
            except Exception as exc:
                logger.warning("transport %s is invalid and will be skipped: %s", name, exc)
        candidates.append(self.fallback)
        return candidates

    async def connect(self) -> None:
        async with self._lock:
            await self.fallback.connect()
            errors = []
            for candidate in self._candidates():
                try:
                    await asyncio.wait_for(candidate.connect(), timeout=5)
                    self.active = candidate
                    self.state = "connected" if candidate is not self.fallback else ("degraded" if errors else "connected")
                    self.last_error = "; ".join(errors)[-1024:]
                    return
                except Exception as exc:
                    errors.append(f"{candidate.name}: {exc}")
                    with suppress(Exception):
                        await candidate.close()
            self.active = self.fallback
            self.state = "degraded"
            self.last_error = "; ".join(errors)[-1024:]

    async def close(self) -> None:
        if self.active is not self.fallback:
            with suppress(Exception):
                await self.active.close()
        await self.fallback.close()
        self.state = "disconnected"

    async def publish(self, event: IntelligenceEvent) -> str:
        # Broadcast to in-process websocket/API consumers even when durable
        # transport is unavailable. Slow clients are dropped, never allowed to
        # block the bus.
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                with suppress(ValueError):
                    self._subscribers.remove(queue)
        try:
            await self.active.publish(event)
            return self.active.name
        except Exception as exc:
            self.state = "degraded"
            self.last_error = str(exc)[:1024]
            if self.active is not self.fallback:
                failed = self.active
                with suppress(Exception):
                    await failed.close()
                self.active = self.fallback
                await self.fallback.publish(event)
                return self.fallback.name
            raise

    async def subscribe(self, maxsize: int = 1000) -> AsyncIterator[IntelligenceEvent]:
        queue: asyncio.Queue[IntelligenceEvent] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            with suppress(ValueError):
                self._subscribers.remove(queue)

    async def health(self) -> Dict[str, object]:
        transport = await self.active.health()
        fallback = await self.fallback.health()
        return {"status": self.state, "active": self.active.name, "transport": transport,
                "fallback": fallback, "last_error": self.last_error, "subscribers": len(self._subscribers)}
