from typing import Dict


class TaskObserver:
    """Observe task execution output and detect suspicious or abnormal behavior."""

    def observe(self, task: Dict, execution_result: Dict) -> Dict:
        status = execution_result.get("status")
        verification = task.get("verification", "")
        notes = []

        if status == "success":
            notes.append("Task executed successfully.")
        elif status == "simulated":
            notes.append("Task was simulated for safety.")
        else:
            notes.append("Task execution returned an error or failed.")

        if "backup" in verification.lower() or "recovery" in verification.lower():
            notes.append("Task includes recovery-related verification and requires careful review.")

        output = execution_result.get("output")
        if isinstance(output, str) and "error" in output.lower():
            notes.append("Output contains error keywords.")

        return {
            "task_id": task.get("task_id"),
            "status": status,
            "notes": notes,
            "observation": "; ".join(notes) if notes else "No issues detected.",
        }
