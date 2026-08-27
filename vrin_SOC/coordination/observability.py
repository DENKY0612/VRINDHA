"""Per-agent observability: health, status, metrics, latency, error counts.

Every coordination agent inherits :class:`BaseAgent` so the dashboard and the
``/agents/health`` endpoint can report, for each agent:

    health, status, events_processed, events_failed, average_latency_ms,
    last_activity, error_count, model (when applicable)

A failed agent is reported as ``degraded`` — never as healthy.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .event_bus import EventBus, event_bus
from .schemas import utc_now_iso


class AgentMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.processed = 0
        self.failed = 0
        self.total_latency_ms = 0.0
        self.last_activity: Optional[str] = None
        self.errors: List[str] = []
        self.extra: Dict[str, Any] = {}

    def record(self, ok: bool, latency_ms: float) -> None:
        with self._lock:
            self.processed += 1
            self.total_latency_ms += latency_ms
            self.last_activity = utc_now_iso()
            if not ok:
                self.failed += 1
                self.errors.append(f"{utc_now_iso()}: handler error")
                self.errors = self.errors[-50:]

    def record_error(self, message: str) -> None:
        with self._lock:
            self.failed += 1
            self.last_activity = utc_now_iso()
            self.errors.append(f"{utc_now_iso()}: {message[:256]}")
            self.errors = self.errors[-50:]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            avg = (self.total_latency_ms / self.processed) if self.processed else 0.0
            return {
                "events_processed": self.processed,
                "events_failed": self.failed,
                "error_count": self.failed,
                "average_latency_ms": round(avg, 3),
                "last_activity": self.last_activity,
                "recent_errors": self.errors[-5:],
                "extra": dict(self.extra),
            }


class BaseAgent:
    """Common agent behavior: identity, metrics, bus wiring, graceful failure."""

    #: Stable identity used in the hive registry, provenance and audit logs.
    name: str = "base_agent"
    kind: str = "sensor"
    capabilities: List[str] = []
    agent_version: str = "1.0"

    def __init__(self, bus: Optional[EventBus] = None) -> None:
        self.bus = bus or event_bus
        self.metrics = AgentMetrics()
        self._running = True
        self._error_streak = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        self._running = True
        self.register_in_hive()

    def stop(self) -> None:
        self._running = False

    def register_in_hive(self) -> None:
        """Best-effort registration in the existing hive layer (never fatal)."""
        try:
            from vrin_SOC.hive.coordinator import hive

            if not hive.registry.get(self.name):
                hive.register_agent(self.name, self.kind, self.capabilities,
                                    {"agent_version": self.agent_version, "layer": "coordination"})
                hive.heartbeat_agent(self.name)
        except Exception:  # noqa: BLE001 — hive must never break the coordination layer
            pass

    @property
    def healthy(self) -> bool:
        return self._running and self._error_streak < 5

    def _before(self) -> float:
        return time.perf_counter()

    def _after(self, started: float, ok: bool = True) -> None:
        latency = (time.perf_counter() - started) * 1000
        self.metrics.record(ok, latency)
        self._error_streak = 0 if ok else self._error_streak + 1

    # ------------------------------------------------------------------
    # Observability contract (spec §26)
    # ------------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        base = self.metrics.snapshot()
        return {
            "agent": self.name,
            "version": self.agent_version,
            "status": "healthy" if self.healthy else "degraded",
            "health": "healthy" if self.healthy else "degraded",
            "capabilities": list(self.capabilities),
            "model": self._model_info(),
            **base,
        }

    def status(self) -> Dict[str, Any]:
        return self.health()

    def _model_info(self) -> Optional[Dict[str, Any]]:
        return None

    # ------------------------------------------------------------------
    # Helpers for concrete agents
    # ------------------------------------------------------------------
    def run_guarded(self, fn, *args, **kwargs):
        """Run ``fn`` with metric tracking and graceful failure handling."""
        started = self._before()
        try:
            result = fn(*args, **kwargs)
            self._after(started, ok=True)
            return result
        except Exception as exc:  # noqa: BLE001
            self._after(started, ok=False)
            self.metrics.record_error(str(exc))
            return {
                "status": "error",
                "agent": self.name,
                "error": str(exc)[:512],
                "degraded": True,
                "note": "SOC continues operating; this agent's contribution is marked unavailable.",
            }


__all__ = ["AgentMetrics", "BaseAgent"]
