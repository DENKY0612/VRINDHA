"""Swarm dispatcher — routes tasks to the best-fit agent(s).

The dispatcher uses the registry to pick candidate agents based on
capability matching, current load, and priority.  Results are
aggregated into a single response for the caller (typically the Brain).
"""

from __future__ import annotations

from datetime import datetime
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

from .models import AgentRecord, AgentState, SwarmTask, TaskPriority
from .registry import AgentRegistry


class SwarmDispatcher:
    """Coordinate multi-agent task execution through the hive."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry
        self._tasks: Dict[int, SwarmTask] = {}
        self._next_id = 1
        self._lock = Lock()
        self._handlers: Dict[str, Callable[..., Dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------
    def register_handler(self, capability: str, handler: Callable[..., Dict[str, Any]]) -> None:
        """Register a callable that executes work for a given capability."""
        self._handlers[capability] = handler

    def unregister_handler(self, capability: str) -> None:
        self._handlers.pop(capability, None)

    # ------------------------------------------------------------------
    # Task creation
    # ------------------------------------------------------------------
    def create_task(
        self,
        command: str,
        priority: TaskPriority = TaskPriority.NORMAL,
        required_capabilities: Optional[List[str]] = None,
    ) -> SwarmTask:
        """Create a task and assign it to matching agents."""
        with self._lock:
            task_id = self._next_id
            self._next_id += 1

        candidates = self._select_agents(required_capabilities)
        task = SwarmTask(
            task_id=task_id,
            command=command,
            priority=priority,
            assigned_agents=[agent.name for agent in candidates],
            status="pending" if not candidates else "dispatched",
        )

        with self._lock:
            self._tasks[task_id] = task

        # Mark assigned agents as busy
        for agent in candidates:
            self._registry.set_state(agent.name, AgentState.BUSY)

        return task

    def complete_task(self, task_id: int, results: Dict[str, Any], status: str = "completed") -> Optional[SwarmTask]:
        """Mark a task as completed (or failed) and release agents."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            task.results.update(results)
            task.status = status
            task.completed_at = datetime.now().isoformat()

        # Release agents back to active
        for agent_name in task.assigned_agents:
            self._registry.set_state(agent_name, AgentState.ACTIVE)

        return task

    def get_task(self, task_id: int) -> Optional[SwarmTask]:
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self, status: Optional[str] = None) -> List[SwarmTask]:
        with self._lock:
            if status:
                return [t for t in self._tasks.values() if t.status == status]
            return list(self._tasks.values())

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def dispatch_task(self, task_id: int) -> Dict[str, Any]:
        """Execute a task by invoking registered handlers for assigned agents."""
        task = self.get_task(task_id)
        if task is None:
            return {"status": "error", "message": f"Task {task_id} not found"}

        if task.status != "dispatched":
            return {"status": "error", "message": f"Task {task_id} is {task.status}, not dispatched"}

        results: Dict[str, Any] = {}
        for agent_name in task.assigned_agents:
            agent = self._registry.get(agent_name)
            if agent is None:
                results[agent_name] = {"status": "error", "message": "Agent not found"}
                continue

            # Find a matching handler
            handler = None
            for cap in agent.capabilities:
                if cap in self._handlers:
                    handler = self._handlers[cap]
                    break

            if handler is None:
                results[agent_name] = {
                    "status": "skipped",
                    "message": f"No handler registered for agent capabilities: {agent.capabilities}",
                }
                continue

            try:
                result = handler(task.command, agent_name, task.priority.value)
                results[agent_name] = result if isinstance(result, dict) else {"output": result}
            except Exception as exc:
                results[agent_name] = {"status": "error", "message": str(exc)[:500]}

        final_status = "completed"
        if all(r.get("status") == "error" for r in results.values()):
            final_status = "failed"

        self.complete_task(task_id, results, final_status)
        return {
            "task_id": task_id,
            "status": final_status,
            "command": task.command,
            "results": results,
        }

    # ------------------------------------------------------------------
    # Agent selection
    # ------------------------------------------------------------------
    def _select_agents(self, required_capabilities: Optional[List[str]] = None) -> List[AgentRecord]:
        """Pick the best-fit agents for a task based on capabilities and load."""
        if not required_capabilities:
            # No specific capability required — pick all active agents
            return self._registry.active_agents()

        candidates: List[AgentRecord] = []
        for cap in required_capabilities:
            matches = self._registry.find_by_capability(cap)
            for agent in matches:
                if agent not in candidates:
                    candidates.append(agent)

        # Prefer agents with lower load (not already busy)
        candidates.sort(key=lambda a: (a.state == AgentState.BUSY, a.name))
        return candidates

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._tasks)
            pending = sum(1 for t in self._tasks.values() if t.status == "pending")
            dispatched = sum(1 for t in self._tasks.values() if t.status == "dispatched")
            completed = sum(1 for t in self._tasks.values() if t.status == "completed")
            failed = sum(1 for t in self._tasks.values() if t.status == "failed")
            return {
                "total_tasks": total,
                "pending": pending,
                "dispatched": dispatched,
                "completed": completed,
                "failed": failed,
                "handlers_registered": list(self._handlers.keys()),
            }
