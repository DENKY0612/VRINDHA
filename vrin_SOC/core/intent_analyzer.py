"""
Intent Analysis Module - Dharma Engine prerequisite
Detects educational vs malicious intent per Gita ethics mapping
"""
from typing import Dict
import re

class IntentAnalyzer:
    """
    Analyzes user command for intent
    Keywords: 
    - suspicious: hack, steal, bypass, crack, exploit, unauthorized
    - safe: test, learn, secure, protect, audit, scan my system, defensive
    """
    
    SUSPICIOUS_KEYWORDS = ["hack", "steal", "bypass", "crack", "exploit", "unauthorized", "break into", "deface", "ransom", "blackmail"]
    MALICIOUS_KEYWORDS = ["steal data", "hack this website without", "ddos", "destroy", "delete database", "ransomware"]
    SAFE_KEYWORDS = ["test", "learn", "secure", "protect", "audit", "my system", "defensive", "educational", "authorized", "my network", "lab", "vulnerability assessment"]
    
    def analyze(self, command: str) -> Dict:
        cmd_lower = command.lower()
        
        # Check malicious first
        for kw in self.MALICIOUS_KEYWORDS:
            if kw in cmd_lower:
                return {
                    "intent": "malicious",
                    "confidence": "high",
                    "matched": kw,
                    "reason": f"Detected malicious phrase '{kw}'"
                }
        
        # Check suspicious
        suspicious_hits = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in cmd_lower]
        safe_hits = [kw for kw in self.SAFE_KEYWORDS if kw in cmd_lower]
        
        if suspicious_hits and not safe_hits:
            return {
                "intent": "suspicious",
                "confidence": "medium",
                "matched": suspicious_hits,
                "reason": "Potentially harmful intent without educational context"
            }
        
        if suspicious_hits and safe_hits:
            return {
                "intent": "safe",
                "confidence": "medium",
                "matched": safe_hits,
                "reason": "Educational / authorized context overrides suspicious keywords",
                "note": f"Suspicious hits {suspicious_hits} but safe context {safe_hits}"
            }
        
        if safe_hits:
            return {
                "intent": "safe",
                "confidence": "high",
                "matched": safe_hits,
                "reason": "Clear educational/defensive intent"
            }
        
        # Default neutral = safe but low confidence
        return {
            "intent": "safe",
            "confidence": "low",
            "matched": [],
            "reason": "No harmful intent detected"
        }

# Global instance
intent_analyzer = IntentAnalyzer()
