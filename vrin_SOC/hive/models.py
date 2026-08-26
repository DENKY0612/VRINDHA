"""Data models for the Hive coordination layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentState(str, Enum):
    """Lifecycle states for a registered agent."""

    REGISTERED = "registered"
    ACTIVE = "active"
    BUSY = "busy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DISABLED = "disabled"


class TaskPriority(str, Enum):
    """Priority levels for swarm-dispatched tasks."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentRecord:
    """Registration record for a single agent in the hive."""

    name: str
    kind: str  # "red", "blue", "sensor", "ml", "tool"
    state: AgentState = AgentState.REGISTERED
    capabilities: List[str] = field(default_factory=list)
    last_heartbeat: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def heartbeat(self) -> None:
        self.last_heartbeat = datetime.now().isoformat()
        if self.state == AgentState.OFFLINE:
            self.state = AgentState.ACTIVE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "state": self.state.value,
            "capabilities": list(self.capabilities),
            "last_heartbeat": self.last_heartbeat,
            "metadata": dict(self.metadata),
            "registered_at": self.registered_at,
        }


@dataclass
class SwarmTask:
    """A task dispatched to one or more agents through the hive."""

    task_id: int
    command: str
    priority: TaskPriority = TaskPriority.NORMAL
    assigned_agents: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, dispatched, completed, failed
    results: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "command": self.command,
            "priority": self.priority.value,
            "assigned_agents": list(self.assigned_agents),
            "status": self.status,
            "results": dict(self.results),
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class HiveSnapshot:
    """Point-in-time snapshot of the entire hive."""

    agents: Dict[str, AgentRecord] = field(default_factory=dict)
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agents": {name: rec.to_dict() for name, rec in self.agents.items()},
            "active_tasks": self.active_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "timestamp": self.timestamp,
        }
