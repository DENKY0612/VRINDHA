"""Agent registry — tracks every agent known to the hive.

Agents register at startup (or on first use) and periodically heartbeat.
The registry flags stale agents as ``OFFLINE`` and exposes a lookup API
for the swarm dispatcher and the Brain.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional

from .models import AgentRecord, AgentState


DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 300  # 5 minutes


class AgentRegistry:
    """Thread-safe, in-process agent registry."""

    def __init__(self, heartbeat_timeout: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS) -> None:
        self._agents: Dict[str, AgentRecord] = {}
        self._lock = Lock()
        self._heartbeat_timeout = heartbeat_timeout

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register(
        self,
        name: str,
        kind: str,
        capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentRecord:
        """Register (or re-register) an agent by name."""
        with self._lock:
            existing = self._agents.get(name)
            if existing is not None:
                existing.kind = kind
                existing.capabilities = list(capabilities or existing.capabilities)
                existing.metadata = dict(metadata or existing.metadata)
                existing.heartbeat()
                existing.state = AgentState.ACTIVE
                return existing
            record = AgentRecord(
                name=name,
                kind=kind,
                state=AgentState.ACTIVE,
                capabilities=list(capabilities or []),
                metadata=dict(metadata or {}),
            )
            record.heartbeat()
            self._agents[name] = record
            return record

    def deregister(self, name: str) -> bool:
        with self._lock:
            return self._agents.pop(name, None) is not None

    # ------------------------------------------------------------------
    # Heartbeat & state
    # ------------------------------------------------------------------
    def heartbeat(self, name: str) -> Optional[AgentRecord]:
        with self._lock:
            record = self._agents.get(name)
            if record is not None:
                record.heartbeat()
            return record

    def set_state(self, name: str, state: AgentState) -> Optional[AgentRecord]:
        with self._lock:
            record = self._agents.get(name)
            if record is not None:
                record.state = state
            return record

    def reap_stale(self) -> List[str]:
        """Mark agents whose heartbeat has exceeded the timeout as OFFLINE."""
        cutoff = datetime.now() - timedelta(seconds=self._heartbeat_timeout)
        reaped: List[str] = []
        with self._lock:
            for record in self._agents.values():
                if record.state in (AgentState.DISABLED, AgentState.OFFLINE):
                    continue
                if not record.last_heartbeat:
                    continue
                try:
                    last = datetime.fromisoformat(record.last_heartbeat)
                except ValueError:
                    continue
                if last < cutoff:
                    record.state = AgentState.OFFLINE
                    reaped.append(record.name)
        return reaped

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get(self, name: str) -> Optional[AgentRecord]:
        with self._lock:
            record = self._agents.get(name)
            return record

    def all_agents(self) -> Dict[str, AgentRecord]:
        with self._lock:
            return {name: rec for name, rec in self._agents.items()}

    def by_kind(self, kind: str) -> List[AgentRecord]:
        with self._lock:
            return [rec for rec in self._agents.values() if rec.kind == kind]

    def active_agents(self) -> List[AgentRecord]:
        with self._lock:
            return [
                rec
                for rec in self._agents.values()
                if rec.state in (AgentState.ACTIVE, AgentState.BUSY)
            ]

    def find_by_capability(self, capability: str) -> List[AgentRecord]:
        with self._lock:
            return [
                rec
                for rec in self._agents.values()
                if capability in rec.capabilities
                and rec.state in (AgentState.ACTIVE, AgentState.BUSY)
            ]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            counts: Dict[str, int] = {}
            for rec in self._agents.values():
                counts[rec.state.value] = counts.get(rec.state.value, 0) + 1
            return {
                "total": len(self._agents),
                "by_state": counts,
                "agents": [rec.to_dict() for rec in self._agents.values()],
            }
