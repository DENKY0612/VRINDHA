"""
Planning Engine Prompt - Super Intelligence Layer
Responsibilities: Break tasks into steps, simulate outcomes before execution
Example Task: Secure system -> Plan: 1. Scan network 2. Detect vulnerabilities 3. Prioritize risks 4. Apply fixes
"""
from typing import Dict, List
from .error_handler import ErrorHandler
import datetime

class PlanningEngine:
    def plan(self, task: str) -> Dict:
        try:
            task_lower = task.lower()
            
            # Predefined plans for common tasks
            if "secure system" in task_lower or "secure my system" in task_lower:
                steps = [
                    {"step": 1, "action": "scan network", "tool": "nmap", "risk": "Low", "desc": "Discover live hosts and open ports"},
                    {"step": 2, "action": "detect vulnerabilities", "tool": "nikto / VulnAgent", "risk": "Low", "desc": "Identify vulnerabilities via scanning"},
                    {"step": 3, "action": "analyze threats", "tool": "ThreatAgent", "risk": "Low", "desc": "Assign risk levels"},
                    {"step": 4, "action": "respond", "tool": "Response Engine", "risk": "Medium", "desc": "Block malicious IPs, kill suspicious processes if High risk"},
                    {"step": 5, "action": "log and report", "tool": "SIEM", "risk": "Low", "desc": "Store all actions in SIEM for audit"}
                ]
            elif "scan network" in task_lower:
                steps = [
                    {"step": 1, "action": "validate target", "tool": "authorization", "risk": "Low"},
                    {"step": 2, "action": "ask confirmation", "tool": "manual", "risk": "Low"},
                    {"step": 3, "action": "run nmap", "tool": "nmap", "risk": "Medium"},
                    {"step": 4, "action": "parse results", "tool": "recon agent", "risk": "Low"}
                ]
            elif "web test" in task_lower or "web scan" in task_lower:
                steps = [
                    {"step": 1, "action": "whois lookup", "tool": "whois"},
                    {"step": 2, "action": "directory busting", "tool": "gobuster/dirb"},
                    {"step": 3, "action": "vulnerability scan", "tool": "nikto"},
                    {"step": 4, "action": "analyze", "tool": "VulnAgent"}
                ]
            else:
                # Generic plan
                steps = [
                    {"step": 1, "action": "analyze request", "tool": "Brain", "desc": f"Analyze '{task}'"},
                    {"step": 2, "action": "classify", "tool": "intent + dharma", "desc": "Check ethics and safety"},
                    {"step": 3, "action": "execute appropriate agent/tool", "tool": "agents", "desc": "Route to correct module"},
                    {"step": 4, "action": "log outcome", "tool": "SIEM", "desc": "Store results for memory and learning"}
                ]
            
            # Simulate outcomes
            simulations = []
            for s in steps:
                simulations.append({
                    "step": s["step"],
                    "simulated_outcome": f"Simulated success for {s['action']}",
                    "risk_evaluation": s.get("risk", "Low"),
                    "requires_confirmation": s.get("risk", "Low") in ["Medium", "High", "Critical"]
                })
            
            return {
                "status": "success",
                "task": task,
                "plan": steps,
                "simulations": simulations,
                "total_steps": len(steps),
                "estimated_risk": "Medium" if len([s for s in steps if s.get("risk") in ["High","Critical"]])>0 else "Low",
                "requires_approval": any(s.get("risk","Low") in ["High","Critical"] for s in steps),
                "timestamp": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "PlanningEngine.plan")

planning_engine = PlanningEngine()
