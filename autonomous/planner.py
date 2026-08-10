import uuid
from typing import Dict, List
from .models import RiskLevel

ACTION_REGISTRY = {
    "system_status": "system_status",
    "package_check": "package_check",
    "package_update": "package_update",
    "service_status": "service_status",
    "service_restart": "service_restart",
    "log_analysis": "log_analysis",
    "network_status": "network_status",
    "firewall_status": "firewall_status",
    "firewall_block_ip": "firewall_block_ip",
    "rootkit_scan": "rootkit_scan",
    "ids_status": "ids_status",
    "report_generation": "report_generation",
    "backup": "backup",
    "anomaly_detection": "anomaly_detection",
    "risk_scoring": "risk_scoring",
}


class Planner:
    """Decompose goals into structured tasks with bounded actions."""

    def plan_goal(self, goal: Dict) -> List[Dict]:
        category = goal.get("category", "unknown")
        plan = []

        if category in ["security_update", "system_maintenance"]:
            plan = [
                self._build_task("Identify operating system", "system_status", "system_status", RiskLevel.LOW, "Check local OS details", 15),
                self._build_task("Identify package manager", "package_check", "package_check", RiskLevel.LOW, "Determine package manager and backend health", 20),
                self._build_task("Check available updates", "package_check", "package_check", RiskLevel.LOW, "Collect available security updates", 30),
                self._build_task("Classify updates", "package_check", "package_check", RiskLevel.LOW, "Label updates with security priority", 20),
                self._build_task("Check disk space", "system_status", "system_status", RiskLevel.LOW, "Ensure enough disk space for updates", 15),
                self._build_task("Check package manager health", "package_check", "package_check", RiskLevel.LOW, "Verify package database and lock state", 20),
                self._build_task("Create recovery point if supported", "backup", "backup", RiskLevel.MEDIUM, "Prepare rollback support or snapshot", 40),
                self._build_task("Install approved security updates", "package_update", "package_update", RiskLevel.MEDIUM, "Apply security-only updates", 60),
                self._build_task("Verify installed packages", "package_check", "package_check", RiskLevel.LOW, "Confirm update installation succeeded", 25),
                self._build_task("Check affected services", "service_status", "service_status", RiskLevel.LOW, "Confirm services are healthy", 30),
                self._build_task("Run post-update security checks", "system_status", "system_status", RiskLevel.LOW, "Verify system integrity after update", 30),
                self._build_task("Generate report", "report_generation", "report_generation", RiskLevel.LOW, "Produce an update summary report", 20),
            ]
        elif category == "security_monitoring":
            plan = [
                self._build_task("Check system health", "system_status", "system_status", RiskLevel.LOW, "Collect CPU, memory, and disk metrics", 20),
                self._build_task("Analyze security logs", "log_analysis", "log_analysis", RiskLevel.LOW, "Review recent security and authentication logs", 30),
                self._build_task("Inspect authentication events", "ids_status", "ids_status", RiskLevel.LOW, "Detect suspicious login activity", 30),
                self._build_task("Inspect running processes", "system_status", "system_status", RiskLevel.LOW, "Find suspicious process activity", 25),
                self._build_task("Inspect network connections", "network_status", "network_status", RiskLevel.LOW, "Check unusual inbound/outbound connections", 25),
                self._build_task("Review firewall and IDS alerts", "firewall_status", "firewall_status", RiskLevel.LOW, "Collect recent defensive alerts", 25),
                self._build_task("Summarize security posture", "report_generation", "report_generation", RiskLevel.LOW, "Draft a monitoring summary", 20),
            ]
        elif category == "log_analysis" or category == "threat_analysis":
            plan = [
                self._build_task("Collect last 24 hours of logs", "log_analysis", "log_analysis", RiskLevel.LOW, "Retrieve security-relevant logs", 30),
                self._build_task("Identify suspicious patterns", "anomaly_detection", "anomaly_detection", RiskLevel.LOW, "Detect anomalies and threat indicators", 40),
                self._build_task("Score risk levels", "risk_scoring", "risk_scoring", RiskLevel.LOW, "Assign risk scores to findings", 20),
                self._build_task("Draft analysis report", "report_generation", "report_generation", RiskLevel.LOW, "Create a findings summary", 20),
            ]
        elif category == "report_generation":
            plan = [
                self._build_task("Gather security event data", "log_analysis", "log_analysis", RiskLevel.LOW, "Collect logs and alert history", 30),
                self._build_task("Analyze incidents and trends", "anomaly_detection", "anomaly_detection", RiskLevel.LOW, "Identify meaningful security changes", 40),
                self._build_task("Compile summary report", "report_generation", "report_generation", RiskLevel.LOW, "Generate a structured security report", 30),
                self._build_task("Review recommended actions", "knowledge_base", "knowledge_base", RiskLevel.LOW, "Recommend next steps and mitigation", 20),
            ]
        else:
            plan = [
                self._build_task("Analyze request", "system_status", "system_status", RiskLevel.LOW, "Interpret the goal and identify bounded defensive actions", 20),
                self._build_task("Classify risk and scope", "system_status", "system_status", RiskLevel.LOW, "Determine whether the requested objective is safe and in scope", 20),
                self._build_task("Prepare safe plan", "report_generation", "report_generation", RiskLevel.LOW, "Generate a safe task plan for review", 20),
            ]

        return plan

    def _build_task(self, description: str, action_type: str, tool: str, risk: str, verification: str, timeout: int) -> Dict:
        return {
            "task_id": uuid.uuid4().hex,
            "description": description,
            "action_type": action_type,
            "tool": ACTION_REGISTRY.get(tool, tool),
            "arguments": {},
            "risk": risk,
            "requires_approval": risk in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value],
            "rollback_strategy": "restore_previous_state" if tool in ["package_update", "service_restart", "backup"] else "none",
            "verification": verification,
            "timeout": timeout,
        }
