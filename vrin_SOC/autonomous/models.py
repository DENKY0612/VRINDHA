from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional
import json


class AutonomyLevel(str, Enum):
    MANUAL = "manual"
    ASSISTED = "assisted"
    DEFENCE = "defence"
    AUTONOMOUS = "autonomous"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GoalStatus(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    VALIDATING = "validating"
    WAITING_APPROVAL = "waiting_approval"
    READY = "ready"
    RUNNING = "running"
    OBSERVING = "observing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    RECOVERY_REQUIRED = "recovery_required"
    PARTIAL_SUCCESS = "partial_success"


class TaskStatus(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    VALIDATING = "validating"
    WAITING_APPROVAL = "waiting_approval"
    READY = "ready"
    RUNNING = "running"
    OBSERVING = "observing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    RECOVERY_REQUIRED = "recovery_required"
    PARTIAL_SUCCESS = "partial_success"


@dataclass
class GoalRecord:
    goal_text: str
    category: str
    priority: str
    autonomy_level: str
    scope: str
    requires_confirmation: bool
    status: str = GoalStatus.CREATED.value
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "goal_text": self.goal_text,
            "category": self.category,
            "priority": self.priority,
            "autonomy_level": self.autonomy_level,
            "scope": self.scope,
            "requires_confirmation": int(self.requires_confirmation),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class TaskRecord:
    task_id: str
    goal_id: int
    description: str
    action_type: str
    tool: str
    arguments: Dict = field(default_factory=dict)
    risk: str = RiskLevel.LOW.value
    requires_approval: bool = False
    rollback_strategy: str = "none"
    verification: str = "none"
    timeout: int = 30
    status: str = TaskStatus.PLANNED.value
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "goal_id": self.goal_id,
            "description": self.description,
            "action_type": self.action_type,
            "tool": self.tool,
            "arguments": self.arguments,
            "risk": self.risk,
            "requires_approval": int(self.requires_approval),
            "rollback_strategy": self.rollback_strategy,
            "verification": self.verification,
            "timeout": self.timeout,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
