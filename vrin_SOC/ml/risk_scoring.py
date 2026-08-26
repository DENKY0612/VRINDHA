"""
Risk Scoring System - Phase 4 (and Data Science Role #4)
Assign scores to events
Example: {ip: 192.168.1.10, risk_score: 85, reason: multiple failed attempts + unusual port}
This becomes core feature for startup product per both PDFs
"""
from datetime import datetime
from typing import Dict, List
import re
from vrin_SOC.core.error_handler import ErrorHandler

class RiskScoring:
    def __init__(self):
        self.name = "RiskScoring"
    
    def score(self, event: Dict) -> Dict:
        try:
            score = 0
            reasons = []
            
            # Extract IP if present
            ip = event.get("ip") or event.get("source_ip") or "unknown"
            
            # Parse events list or single command
            text = ""
            if isinstance(event, dict):
                text = str(event.get("events","")) + " " + str(event.get("command","")) + " " + str(event.get("result","")) + " " + str(event)
            else:
                text = str(event)
            text_lower = text.lower()
            
            # Scoring rules per data science blueprint
            if "failed login" in text_lower or "failed password" in text_lower:
                # Count occurrences
                count = len(re.findall(r"failed", text_lower))
                score += min(count * 15, 60)
                reasons.append(f"Multiple failed logins ({count} attempts)")
            
            if any(p in text_lower for p in ["4444", "6666", "1337", "unusual port"]):
                score += 25
                reasons.append("Unusual port access")
            
            if "rootkit" in text_lower or "malware" in text_lower:
                score += 90
                reasons.append("Malware/rootkit indicator")
            
            if "attack" in text_lower or "breach" in text_lower or "intrusion" in text_lower:
                score += 40
                reasons.append("Attack keywords detected")
            
            if "scan" in text_lower and "multiple" in text_lower:
                score += 20
                reasons.append("Multiple scans - reconnaissance")
            
            # Cap at 100
            score = min(score, 100)
            
            # Determine level
            if score >= 80:
                level = "Critical"
            elif score >= 60:
                level = "High"
            elif score >= 30:
                level = "Medium"
            else:
                level = "Low"
            
            return {
                "ip": ip,
                "risk_score": score,
                "risk_level": level,
                "reason": " + ".join(reasons) if reasons else "No significant risk indicators, normal behavior",
                "reasons": reasons,
                "timestamp": datetime.now().isoformat(),
                "model": "Rule-based risk scoring (future: ML-enhanced)"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "RiskScoring.score")
    
    def score_ip_history(self, ip: str, events: List[Dict]) -> Dict:
        """Score based on history for an IP"""
        try:
            combined_text = " ".join([str(e) for e in events])
            result = self.score({"ip": ip, "events": events, "combined": combined_text})
            result["history_count"] = len(events)
            return result
        except Exception as e:
            return ErrorHandler.handle_exception(e, "RiskScoring.score_ip_history")

risk_scoring = RiskScoring()
