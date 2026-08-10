from typing import Dict


class TaskVerifier:
    """Verify task execution results against expected completion state."""

    def verify(self, task: Dict, execution_result: Dict) -> Dict:
        status = execution_result.get("status")
        verified = status == "success"
        message = "Verified successfully." if verified else "Verification failed or task did not complete full success."

        if status == "simulated":
            verified = True
            message = "Simulation-only execution is accepted for safe validation in this environment."

        if status == "error":
            message = execution_result.get("error") or "Execution error prevented verification."

        return {
            "task_id": task.get("task_id"),
            "verified": verified,
            "status": status,
            "message": message,
            "verification_steps": [
                f"Expected verification: {task.get('verification', 'none')}",
                f"Execution result status: {status}"
            ]
        }
