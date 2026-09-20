"""Shared event bus — the only communication channel between HIVE agents.

Agents never call each other directly for intelligence exchange. They publish
typed :class:`SecurityEvent` objects to the bus and subscribe to event types
they care about. This keeps the architecture:

    Infrastructure → Event Bus → specialized subscribers
    Threat Intel   → Event Bus → specialized subscribers
    Data Science   → Event Bus → SOC Analyst / Commander

The transport is pluggable (:class:`EventTransport`) so the in-memory
implementation can later be swapped for Redis/NATS/Kafka without touching
agents. Delivery is never silent: failures land in a dead-letter queue with
the subscriber and the error, so "a failed dependency pretending to have
succeeded" is impossible by construction.
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional

from .schemas import SecurityEvent

logger = logging.getLogger(__name__)

SubscriberFn = Callable[[SecurityEvent], Optional[Dict[str, Any]]]


class EventTransport:
    """Transport abstraction. In-memory by default; replaceable per deployment."""

    def store(self, event: SecurityEvent) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def peek(self, limit: int) -> List[SecurityEvent]:  # pragma: no cover - interface
        raise NotImplementedError


class InMemoryTransport(EventTransport):
    def __init__(self, capacity: int = 5000) -> None:
        self._events: deque[SecurityEvent] = deque(maxlen=capacity)

    def store(self, event: SecurityEvent) -> None:
        self._events.append(event)

    def peek(self, limit: int) -> List[SecurityEvent]:
        items = list(self._events)
        return items[-limit:]


class EventBus:
    """Thread-safe publish/subscribe/correlate bus with a dead-letter queue."""

    def __init__(self, transport: Optional[EventTransport] = None, history_limit: int = 2000,
                 rate_limit_per_sec: int = 100) -> None:
        self.transport = transport or InMemoryTransport()
        self._lock = threading.RLock()
        self._subscribers: Dict[str, List[Dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self._history: deque[SecurityEvent] = deque(maxlen=history_limit)
        self._dead_letter: deque[Dict[str, Any]] = deque(maxlen=500)
        self.published = 0
        self.delivered = 0
        self.failed = 0
        # Rate limiting (Phase 3)
        self._rate_limit = max(1, rate_limit_per_sec)
        self._emit_timestamps: deque[float] = deque(maxlen=self._rate_limit * 2)

    # ------------------------------------------------------------------
    # Rate limiting helper (Phase 3)
    # ------------------------------------------------------------------
    def _check_rate_limit(self) -> bool:
        """Return True if under rate limit, False if exceeded."""
        now = time.time()
        with self._lock:
            # Remove timestamps older than 1 second
            while self._emit_timestamps and self._emit_timestamps[0] < now - 1.0:
                self._emit_timestamps.popleft()
            if len(self._emit_timestamps) >= self._rate_limit:
                return False
            self._emit_timestamps.append(now)
        return True

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------
    def subscribe(self, event_type: str, fn: SubscriberFn, subscriber: str = "anonymous",
                  wildcard: bool = False) -> str:
        """Register a handler. ``event_type="*"`` or wildcard=True = all types."""
        sub_id = f"sub-{next(self._ids)}"
        with self._lock:
            key = "*" if (wildcard or event_type == "*") else event_type
            self._subscribers.setdefault(key, []).append(
                {"id": sub_id, "subscriber": subscriber, "fn": fn}
            )
        return sub_id

    def unsubscribe(self, sub_id: str) -> bool:
        with self._lock:
            for key in list(self._subscribers):
                before = len(self._subscribers[key])
                self._subscribers[key] = [s for s in self._subscribers[key] if s["id"] != sub_id]
                if len(self._subscribers[key]) != before:
                    return True
        return False

    def _handlers_for(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        with self._lock:
            specific = list(self._subscribers.get(event.event_type, []))
            wildcard = list(self._subscribers.get("*", []))
        return specific + wildcard

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------
    def publish(self, event: SecurityEvent) -> Dict[str, Any]:
        """Validate-persist-deliver. Returns a delivery report.

        Adds TI availability metadata to the event (Phase 3 TI enforcement).
        """
        # Enforce TI availability metadata on every event
        try:
            from .ti_enforcer import ti_enforcer
            ti_enforcer.enrich_event_metadata(event.metadata)
        except Exception:
            # TI enforcer not available - continue without it
            pass

        started = time.perf_counter()
        self.transport.store(event)
        with self._lock:
            self._history.append(event)
            self.published += 1
        report: Dict[str, Any] = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "delivered_to": [],
            "errors": [],
            "duration_ms": 0.0,
        }
        for handler in self._handlers_for(event):
            try:
                result = handler["fn"](event)
                if isinstance(result, dict):
                    # Subscribers may annotate the event with structured output.
                    event.record(**result)
                with self._lock:
                    self.delivered += 1
                report["delivered_to"].append(handler["subscriber"])
            except Exception as exc:  # noqa: BLE001 — bus must survive handler bugs
                with self._lock:
                    self.failed += 1
                    self._dead_letter.append(
                        {
                            "event_id": event.event_id,
                            "subscriber": handler["subscriber"],
                            "error": str(exc)[:512],
                            "at": time.time(),
                        }
                    )
                report["errors"].append(f"{handler['subscriber']}: {str(exc)[:256]}")
                logger.exception("[Bus] subscriber %s failed on %s", handler["subscriber"], event.event_id)
        report["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return report

    def emit(self, **fields: Any) -> SecurityEvent:
        """Convenience: build a SecurityEvent and publish it.
        
        Respects rate limiting (Phase 3) - raises if exceeded.
        """
        if not self._check_rate_limit():
            raise RuntimeError(f"Event bus rate limit exceeded ({self._rate_limit} events/sec)")
        event = SecurityEvent(**fields)
        self.publish(event)
        return event

    # ------------------------------------------------------------------
    # Correlation / lifecycle
    # ------------------------------------------------------------------
    def correlate(self, correlation_id: str) -> List[SecurityEvent]:
        """All events sharing a correlation id (timeline of one investigation)."""
        return [e for e in self._history if e.correlation_id == correlation_id]

    def acknowledge(self, event_id: str, status: str, actor: str = "bus") -> bool:
        """Mark an event's lifecycle status (idempotent, bounded history)."""
        for event in list(self._history):
            if event.event_id == event_id:
                event.status = _coerce_status(status)
                event.provenance.source_agent = event.provenance.source_agent or actor
                return True
        return False

    def update(self, event_id: str, **fields: Any) -> bool:
        for event in list(self._history):
            if event.event_id == event_id:
                event.record(**fields)
                return True
        return False

    def find(self, event_id: str) -> Optional[SecurityEvent]:
        for event in self._history:
            if event.event_id == event_id:
                return event
        return None

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    def dead_letter(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self._dead_letter)[-limit:]

    def stats(self) -> Dict[str, Any]:
        return {
            "published": self.published,
            "delivered": self.delivered,
            "failed": self.failed,
            "subscribers": sum(len(v) for v in self._subscribers.values()),
            "history_size": len(self._history),
            "dead_letter_size": len(self._dead_letter),
            "rate_limit_per_sec": self._rate_limit,
            "recent_emit_rate": len(self._emit_timestamps),
        }


def _coerce_status(value: str):
    from .schemas import EventStatus

    try:
        return EventStatus(value)
    except ValueError:
        return EventStatus.CLOSED


# Process-wide default bus shared by all coordination agents.
event_bus = EventBus()
