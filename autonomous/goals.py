from typing import Dict
from .models import AutonomyLevel


class GoalEngine:
    """Classify high-level user objectives into safe goal metadata."""

    CATEGORY_MAP = [
        {
            "category": "security_update",
            "keywords": ["update my system", "install safe updates", "security updates", "check available updates", "update system safely", "system update"],
            "priority": "normal",
            "autonomy_level": AutonomyLevel.DEFENCE.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "system_maintenance",
            "keywords": ["system maintenance", "clean my system", "health check", "package manager", "check my system"],
            "priority": "normal",
            "autonomy_level": AutonomyLevel.ASSISTED.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "security_monitoring",
            "keywords": ["monitor my system", "while i'm away", "defence mode", "defense mode", "defence mode active", "absence mode", "monitor while", "monitor my system while"],
            "priority": "high",
            "autonomy_level": AutonomyLevel.DEFENCE.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "log_analysis",
            "keywords": ["analyze today's security logs", "analyze security logs", "analyze logs", "investigate logs", "log analysis", "security log analysis"],
            "priority": "normal",
            "autonomy_level": AutonomyLevel.AUTONOMOUS.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "threat_analysis",
            "keywords": ["find unusual authentication activity", "analyze threats", "identify suspicious activity", "threat detection", "detect threats"],
            "priority": "high",
            "autonomy_level": AutonomyLevel.DEFENCE.value,
            "scope": "local_host",
            "requires_confirmation": True,
        },
        {
            "category": "report_generation",
            "keywords": ["generate a security report", "prepare a security report", "prepare report", "security report"],
            "priority": "normal",
            "autonomy_level": AutonomyLevel.AUTONOMOUS.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "performance_analysis",
            "keywords": ["analyze the system performance", "performance analysis", "suggest improvements"],
            "priority": "low",
            "autonomy_level": AutonomyLevel.ASSISTED.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
        {
            "category": "incident_response",
            "keywords": ["incident response", "respond to", "contain", "security incident", "security problem"],
            "priority": "high",
            "autonomy_level": AutonomyLevel.DEFENCE.value,
            "scope": "local_host",
            "requires_confirmation": True,
        },
        {
            "category": "backup",
            "keywords": ["backup", "create recovery point", "restore point", "snapshot"],
            "priority": "normal",
            "autonomy_level": AutonomyLevel.ASSISTED.value,
            "scope": "local_host",
            "requires_confirmation": False,
        },
    ]

    def classify_goal(self, text: str) -> Dict:
        text_lower = text.lower().strip()
        # Direct goal prefix handling
        if text_lower.startswith("goal "):
            text_lower = text_lower[5:].strip()

        for candidate in self.CATEGORY_MAP:
            if any(keyword in text_lower for keyword in candidate["keywords"]):
                return {
                    "goal": text.strip(),
                    "category": candidate["category"],
                    "priority": candidate["priority"],
                    "autonomy_level": candidate["autonomy_level"],
                    "scope": candidate["scope"],
                    "requires_confirmation": candidate["requires_confirmation"],
                }

        meaningful = ["update", "monitor", "analyze", "report", "security", "incident", "backup", "performance"]
        if any(word in text_lower for word in meaningful):
            return {
                "goal": text.strip(),
                "category": "research",
                "priority": "normal",
                "autonomy_level": AutonomyLevel.AUTONOMOUS.value,
                "scope": "local_host",
                "requires_confirmation": False,
            }

        return {
            "goal": text.strip(),
            "category": "unknown",
            "priority": "low",
            "autonomy_level": AutonomyLevel.MANUAL.value,
            "scope": "local_host",
            "requires_confirmation": True,
        }
