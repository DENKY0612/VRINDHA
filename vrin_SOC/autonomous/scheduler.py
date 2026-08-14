from typing import List, Dict, Optional
from .task_manager import task_manager
from .executor import task_executor
from .observer import TaskObserver
from .verifier import TaskVerifier
from .recovery import RecoveryManager
from .policy import AutonomyPolicy
from .models import TaskStatus, GoalStatus


class Scheduler:
    """Schedule and execute autonomous tasks in bounded, observable phases."""

    def __init__(self):
        self.observer = TaskObserver()
        self.verifier = TaskVerifier()
        self.recovery = RecoveryManager()
        self.policy = AutonomyPolicy()

    def run_goal(self, goal_id: int) -> Dict[str, object]:
        goal = task_manager.get_goal(goal_id)
        if not goal:
            return {"status": "error", "message": f"Goal {goal_id} not found."}

        tasks = task_manager.list_tasks(goal_id)
        if not tasks:
            return {"status": "error", "message": "No tasks found for goal."}

        goal_state = GoalStatus.RUNNING.value
        task_manager.update_goal_status(goal_id, goal_state)
        summary = []
        all_success = True
        any_waiting = False
        any_blocked = False
        any_recovery = False

        for task in tasks:
            if task.get("status") in [TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value]:
                summary.append({"task_id": task["task_id"], "status": task["status"], "skipped": True})
                continue

            if task.get("status") == TaskStatus.WAITING_APPROVAL.value:
                summary.append({"task_id": task["task_id"], "status": task["status"], "message": "Waiting for manual approval."})
                any_waiting = True
                all_success = False
                continue

            # Validation phase
            task_manager.update_task_status(task["task_id"], TaskStatus.VALIDATING.value)
            policy_result = self.policy.evaluate_task(task, goal.get("autonomy_level", "manual"))
            if policy_result["decision"] == "deny":
                task_manager.update_task_status(task["task_id"], TaskStatus.BLOCKED.value)
                summary.append({"task_id": task["task_id"], "status": TaskStatus.BLOCKED.value, "reason": policy_result["reason"]})
                any_blocked = True
                all_success = False
                continue
            if policy_result["requires_approval"]:
                task_manager.update_task_status(task["task_id"], TaskStatus.WAITING_APPROVAL.value)
                summary.append({"task_id": task["task_id"], "status": TaskStatus.WAITING_APPROVAL.value, "reason": policy_result["reason"]})
                any_waiting = True
                all_success = False
                continue

            task_manager.update_task_status(task["task_id"], TaskStatus.READY.value)
            task_manager.update_task_status(task["task_id"], TaskStatus.RUNNING.value)

            execution_result = task_executor.execute_task(task)
            observation = self.observer.observe(task, execution_result)
            verification = self.verifier.verify(task, execution_result)

            if verification.get("verified"):
                task_manager.update_task_status(task["task_id"], TaskStatus.COMPLETED.value)
                summary.append({
                    "task_id": task["task_id"],
                    "status": TaskStatus.COMPLETED.value,
                    "execution": execution_result,
                    "observation": observation,
                    "verification": verification,
                })
            else:
                all_success = False
                recovery_result = self.recovery.recover(task, execution_result)
                task_manager.update_task_status(task["task_id"], TaskStatus.RECOVERY_REQUIRED.value)
                summary.append({
                    "task_id": task["task_id"],
                    "status": TaskStatus.RECOVERY_REQUIRED.value,
                    "execution": execution_result,
                    "observation": observation,
                    "verification": verification,
                    "recovery": recovery_result,
                })

        final_status = GoalStatus.COMPLETED.value if all_success else GoalStatus.PARTIAL_SUCCESS.value
        if any_recovery or any(t.get("status") == TaskStatus.RECOVERY_REQUIRED.value for t in tasks):
            final_status = GoalStatus.RECOVERY_REQUIRED.value
        elif any_waiting:
            final_status = GoalStatus.WAITING_APPROVAL.value
        elif any_blocked or any(t.get("status") == TaskStatus.BLOCKED.value for t in tasks):
            final_status = GoalStatus.BLOCKED.value

        task_manager.update_goal_status(goal_id, final_status)
        status_text = "completed" if final_status == GoalStatus.COMPLETED.value else final_status
        return {"status": status_text, "goal_status": final_status, "summary": summary}

    def run_pending_tasks(self, goal_id: Optional[int] = None) -> Dict[str, object]:
        if goal_id is not None:
            return self.run_goal(goal_id)

        self.recover_stuck_tasks()
        pending_tasks = task_manager.get_tasks_by_status([
            TaskStatus.PLANNED.value,
            TaskStatus.READY.value,
            TaskStatus.VALIDATING.value,
            TaskStatus.RUNNING.value,
        ])
        if not pending_tasks:
            return {"status": "idle", "message": "No pending autonomous tasks to execute."}

        processed_goals = set()
        results = []
        for task in pending_tasks:
            goal_id = task.get("goal_id")
            if goal_id in processed_goals:
                continue
            result = self.run_goal(goal_id)
            results.append({"goal_id": goal_id, "result": result})
            processed_goals.add(goal_id)

        return {"status": "processed", "results": results}

    def recover_stuck_tasks(self) -> Dict[str, object]:
        """Recover interrupted or stuck autonomous tasks back to a safe pending state."""
        stuck_tasks = task_manager.recover_unfinished_tasks()
        if not stuck_tasks:
            return {"status": "ok", "message": "No stuck autonomous tasks found."}

        recovered = []
        for task in stuck_tasks:
            original = task.get("status")
            new_status = original
            if original in [TaskStatus.RUNNING.value, TaskStatus.VALIDATING.value, TaskStatus.PLANNED.value, TaskStatus.READY.value]:
                new_status = TaskStatus.PLANNED.value
            elif original == TaskStatus.WAITING_APPROVAL.value:
                new_status = TaskStatus.WAITING_APPROVAL.value

            if new_status != original:
                task_manager.update_task_status(task["task_id"], new_status)
            recovered.append({"task_id": task["task_id"], "from": original, "to": new_status})

        return {"status": "recovered", "recovered_tasks": recovered}
