"""Feed registration, scheduling, health, retry and stale detection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol
import asyncio
import logging

from ..config import TIConfig
from ..database import ThreatDatabase
from ..metrics import metrics
from ..models import FeedStatus
from .base import FeedCollector
from .cisa_kev import CISAKEVCollector
from .mitre import MITREAttackCollector
from .nvd import NVDCollector
from .stix_taxii import STIXTAXIICollector
from .suricata import SuricataCollector
from .zeek import ZeekCollector

logger = logging.getLogger("vrindha.ti.feeds")


class IngestionEngine(Protocol):
    async def ingest_collected(self, item, source: str, reliability: float) -> int: ...
    async def emit_feed_health(self, name: str, status: str, detail: Dict[str, Any]) -> None: ...


class FeedManager:
    def __init__(self, config: TIConfig, database: ThreatDatabase, engine: IngestionEngine):
        self.config = config
        self.database = database
        self.engine = engine
        self.collectors: Dict[str, FeedCollector] = {}
        self.states: Dict[str, FeedStatus] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._stopping = asyncio.Event()
        self._register_defaults()

    def _register_defaults(self) -> None:
        constructors = {
            "cisa_kev": lambda c: CISAKEVCollector(timeout=c["timeout"], reliability=c["reliability"]),
            "nvd": lambda c: NVDCollector(timeout=c["timeout"], reliability=c["reliability"]),
            "mitre_attack": lambda c: MITREAttackCollector(timeout=c["timeout"], reliability=c["reliability"]),
            "stix_taxii": lambda c: STIXTAXIICollector(timeout=c["timeout"], reliability=c["reliability"]),
            "suricata": lambda c: SuricataCollector(self.config.suricata_eve_path, timeout=c["timeout"], reliability=c["reliability"]),
            "zeek": lambda c: ZeekCollector(self.config.zeek_log_dir, timeout=c["timeout"], reliability=c["reliability"]),
        }
        for name, values in self.config.feeds.items():
            values = {**{"enabled": False, "interval": 3600, "timeout": 30, "retry_count": 3, "reliability": 0.5}, **values}
            if name in constructors:
                self.register(constructors[name](values), values)

    def register(self, collector: FeedCollector, settings: Dict[str, Any]) -> None:
        self.collectors[collector.name] = collector
        self._locks[collector.name] = asyncio.Lock()
        state = FeedStatus(name=collector.name, enabled=bool(settings["enabled"]), interval=max(60, int(settings["interval"])),
            timeout=max(1, int(settings["timeout"])), retry_count=max(0, int(settings["retry_count"])),
            reliability=max(0, min(1, float(settings["reliability"]))), status="idle" if settings["enabled"] else "disabled")
        previous = next((item for item in self.database.feed_statuses() if item["name"] == collector.name), None)
        if previous:
            state.last_success = datetime.fromisoformat(previous["last_success"]) if previous.get("last_success") else None
            state.last_failure = datetime.fromisoformat(previous["last_failure"]) if previous.get("last_failure") else None
            state.items_ingested = int(previous.get("items_ingested", 0))
        self.states[collector.name] = state
        self.database.set_feed_status(state)

    async def sync(self, name: str) -> Dict[str, Any]:
        if name not in self.collectors:
            raise KeyError(f"unknown feed: {name}")
        state = self.states[name]
        if not state.enabled:
            return {"name": name, "status": "disabled", "items_ingested": 0}
        async with self._locks[name]:
            state.status = "running"
            state.last_error = ""
            self.database.set_feed_status(state)
            cursor = self.database.feed_cursor(name)
            last_error: Optional[Exception] = None
            for attempt in range(state.retry_count + 1):
                try:
                    batch = await asyncio.wait_for(self.collectors[name].collect(cursor), timeout=state.timeout + 2)
                    ingested = 0
                    # Bound concurrent ingestion while retaining deterministic DB ordering per item.
                    for item in batch.items:
                        ingested += await self.engine.ingest_collected(item, name, state.reliability)
                    state.items_ingested += ingested
                    state.last_success = datetime.now(timezone.utc)
                    state.status = "healthy"
                    self.database.set_feed_status(state, batch.cursor)
                    metrics.inc("feed_success_total")
                    await self.engine.emit_feed_health(name, "healthy", {"items_ingested": ingested, **batch.metadata})
                    logger.info("feed sync succeeded", extra={"source": name, "outcome": "success"})
                    return {"name": name, "status": state.status, "items_ingested": ingested, "attempts": attempt + 1, "metadata": batch.metadata}
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    last_error = exc
                    if attempt < state.retry_count:
                        await asyncio.sleep(min(2 ** attempt, 30))
            state.last_failure = datetime.now(timezone.utc)
            state.status = "error" if state.last_success is None else "degraded"
            state.last_error = str(last_error)[:1024]
            self.database.set_feed_status(state)
            metrics.inc("feed_failure_total")
            await self.engine.emit_feed_health(name, state.status, {"error": state.last_error})
            logger.warning("feed sync failed: %s", state.last_error, extra={"source": name, "outcome": "failure"})
            return {"name": name, "status": state.status, "items_ingested": 0, "error": state.last_error}

    async def sync_all(self) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.config.feed_concurrency)

        async def run(name: str) -> Dict[str, Any]:
            async with semaphore:
                return await self.sync(name)

        return await asyncio.gather(*(run(name) for name, state in self.states.items() if state.enabled))

    async def _run_periodic(self, name: str) -> None:
        if self.config.collect_on_start:
            await self.sync(name)
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.states[name].interval)
            except asyncio.TimeoutError:
                await self.sync(name)

    async def start(self) -> None:
        self._stopping.clear()
        for name, state in self.states.items():
            if state.enabled and name not in self._tasks:
                self._tasks[name] = asyncio.create_task(self._run_periodic(name), name=f"ti-feed-{name}")

    async def stop(self) -> None:
        self._stopping.set()
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()

    def mark_stale(self, now: Optional[datetime] = None) -> int:
        current = now or datetime.now(timezone.utc)
        changed = 0
        for state in self.states.values():
            if state.enabled and state.last_success and current - state.last_success > timedelta(seconds=state.interval * 2):
                state.status = "stale"
                self.database.set_feed_status(state)
                changed += 1
        return changed

    def status(self) -> List[Dict[str, Any]]:
        self.mark_stale()
        return [state.model_dump(mode="json") for state in self.states.values()]
