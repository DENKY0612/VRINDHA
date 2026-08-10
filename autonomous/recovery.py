from typing import Dict


class RecoveryManager:
    """Handle recovery or rollback when task execution fails."""

    def recover(self, task: Dict, execution_result: Dict) -> Dict:
        rollback_strategy = task.get("rollback_strategy", "none")
        if rollback_strategy == "none":
            return {
                "task_id": task.get("task_id"),
                "recovered": False,
                "message": "No rollback strategy defined; manual recovery may be required.",
                "suggestion": "Review the failed task and restore state manually if needed."
            }

        if rollback_strategy == "restore_previous_state":
            return {
                "task_id": task.get("task_id"),
                "recovered": True,
                "message": "A safe recovery path has been simulated for this task.",
                "suggestion": "If this were a real system, restore the previous backup or rollback state."
            }

        return {
            "task_id": task.get("task_id"),
            "recovered": False,
            "message": "Rollback strategy not recognized.",
            "suggestion": "Investigate the task and perform manual recovery."
        }
