"""
Threat Agent - Per DAY 17 and MASTER BLUEPRINT Threat Detection Prompt
Analyze text input for words: attack, breach, malware
Return threat level, plus per advanced blueprint: analyze system logs, tool outputs, detect multiple failed logins, unusual ports, suspicious processes
Assign risk levels: LOW, MEDIUM, HIGH
Return: {threat, risk, confidence}
"""
import re
from typing import Dict
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.error_handler import ErrorHandler
from datetime import datetime

class ThreatAgent:
    def __init__(self):
        self.name = "ThreatAgent"
        self.threat_keywords = ["attack", "breach", "malware", "exploit", "intrusion", "ransomware", "phishing", "ddos"]
        self.high_risk_indicators = ["multiple failed logins", "unusual ports", "suspicious processes", "rootkit", "backdoor"]
    
    def analyze(self, text: str) -> Dict:
        try:
            text_lower = text.lower()
            
            # Basic keyword detection per Day 17
            detected_keywords = [kw for kw in self.threat_keywords if kw in text_lower]
            high_indicators = [ind for ind in self.high_risk_indicators if ind in text_lower]
            
            # Also detect brute force patterns
            failed_login_pattern = re.search(r"(\d+)\s*failed", text_lower)
            failed_count = int(failed_login_pattern.group(1)) if failed_login_pattern else 0
            
            # Port detection
            suspicious_ports = re.findall(r":(4444|1234|6666|1337|8081)\b", text_lower)
            
            # Determine threat level
            if high_indicators or failed_count >= 5 or suspicious_ports or "malware" in text_lower or "breach" in text_lower:
                threat_level = "HIGH"
                risk = "HIGH"
                confidence = "high"
            elif detected_keywords or failed_count >= 2:
                threat_level = "MEDIUM"
                risk = "MEDIUM"
                confidence = "medium"
            else:
                threat_level = "LOW"
                risk = "LOW"
                confidence = "low"
            
            return {
                "agent": self.name,
                "threat_detected": len(detected_keywords) > 0 or len(high_indicators) > 0,
                "threat_level": threat_level,
                "risk_level": risk,
                "risk": risk,
                "confidence": confidence,
                "threat": ", ".join(detected_keywords) if detected_keywords else "No clear threat keywords but analyzed",
                "indicators": detected_keywords + high_indicators,
                "failed_login_attempts": failed_count,
                "suspicious_ports": suspicious_ports,
                "timestamp": datetime.now().isoformat(),
                "raw": text[:500],
                "anomaly_score": 0.9 if threat_level == "HIGH" else 0.5 if threat_level == "MEDIUM" else 0.1
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "ThreatAgent.analyze")
    
    def run(self, log_text: str = "") -> Dict:
        """Alias for analyze to match Brain expectations"""
        return self.analyze(log_text)

threat_agent = ThreatAgent()
