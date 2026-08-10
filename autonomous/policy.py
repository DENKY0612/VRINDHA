from typing import Dict
from .models import RiskLevel, AutonomyLevel


class AutonomyPolicy:
    LOW = RiskLevel.LOW.value
    MEDIUM = RiskLevel.MEDIUM.value
    HIGH = RiskLevel.HIGH.value
    CRITICAL = RiskLevel.CRITICAL.value

    def evaluate_task(self, task: Dict, autonomy_level: str) -> Dict:
        risk = str(task.get("risk", self.LOW)).lower()
        # Default evaluation
        if risk == self.LOW:
            return {"decision": "allow", "requires_approval": False, "reason": "Low risk actions are allowed automatically."}

        if risk == self.MEDIUM:
            if autonomy_level in [AutonomyLevel.DEFENCE.value, AutonomyLevel.AUTONOMOUS.value]:
                return {"decision": "allow", "requires_approval": False, "reason": "Medium risk actions are allowed in defence/autonomous mode when bounded."}
            return {"decision": "review", "requires_approval": True, "reason": "Medium risk actions require review outside defence/autonomous mode."}

        if risk == self.HIGH:
            return {"decision": "review", "requires_approval": True, "reason": "High-risk actions require explicit human approval."}

        if risk == self.CRITICAL:
            return {"decision": "deny", "requires_approval": True, "reason": "Critical actions always require explicit confirmation and are blocked without it."}

        # Fallback conservative
        return {"decision": "review", "requires_approval": True, "reason": "Unknown risk level defaults to review."}

    def evaluate_goal(self, goal: Dict) -> Dict:
        if goal.get("requires_confirmation"):
            return {
                "decision": "review",
                "requires_approval": True,
                "reason": "Goal-level metadata indicates confirmation is required."
            }

        if goal.get("autonomy_level") == AutonomyLevel.MANUAL.value:
            return {
                "decision": "review",
                "requires_approval": True,
                "reason": "Manual goals require operator approval before execution."
            }

        return {
            "decision": "allow",
            "requires_approval": False,
            "reason": "Goal is allowed under current autonomy policy metadata."
        }
