"""
Dharma Engine Module - Ethical Reasoning Layer inspired by Bhagavad Gita
Per MASTER BLUEPRINT: Evaluate whether action is ethical before execution
"""
from typing import Dict
from .gita_engine import gita_engine
from .intent_analyzer import intent_analyzer
from .error_handler import ErrorHandler

class DharmaEngine:
    """
    Evaluates actions for dharma (right) vs adharma (wrong)
    Purpose: moral reasoning layer on top of Vrindha
    AI Decision = Technical Logic + Ethical Check (Gita-based)
    """
    
    # Adharma indicators per blueprint
    ADHARMA_PATTERNS = [
        "unauthorized access",
        "exploitation",
        "data theft",
        "personal gain",
        "revenge",
        "hack this website",
        "steal",
        "bypass security without permission",
        "ddos",
        "deface"
    ]
    
    DHARMA_PATTERNS = [
        "security testing",
        "learning",
        "defense",
        "protect",
        "audit my system",
        "vulnerability assessment",
        "authorized",
        "educational",
        "my network",
        "lab environment"
    ]
    
    HIGH_RISK_TOOLS = ["metasploit", "hashcat", "hydra", "john", "burpsuite", "exploit", "sqlmap"]
    
    def evaluate_action(self, command: str, intent_data: Dict = None) -> Dict:
        """
        Evaluate whether action is ethical
        Output: {decision: allow/deny/warn, reason, risk_level, gita_verse}
        """
        try:
            cmd_lower = command.lower()
            
            # Step 1: Intent analysis
            if intent_data is None:
                intent_data = intent_analyzer.analyze(command)
            
            intent = intent_data.get("intent", "safe")
            
            # Step 2: Check for Adharma
            for pattern in self.ADHARMA_PATTERNS:
                if pattern in cmd_lower:
                    # But check if it's within safe context like "my system"
                    if any(safe in cmd_lower for safe in self.DHARMA_PATTERNS):
                        # If safe context overrides, warn instead of deny
                        guidance = gita_engine.get_ethical_guidance("defense" if "protect" in cmd_lower else "learning")
                        return {
                            "decision": "warn",
                            "reason": f"Potentially sensitive action '{pattern}' but with authorized/safe context - requires confirmation",
                            "risk_level": "medium",
                            "intent": intent,
                            "gita_verse": guidance.get("verse"),
                            "gita_message": guidance.get("message"),
                            "action_type": "defense" if "protect" in cmd_lower else "learning"
                        }
                    # Pure adharma
                    guidance = gita_engine.get_ethical_guidance("attack")
                    return {
                        "decision": "deny",
                        "reason": f"Unauthorized access / harmful intent detected: '{pattern}' violates ethical principles (Dharma)",
                        "risk_level": "high",
                        "intent": intent,
                        "gita_verse": guidance.get("verse"),
                        "gita_message": "Use your skills to protect, not harm. True strength lies in protecting, not exploiting.",
                        "action_type": "attack",
                        "educational": "From Gita: Act with duty (Dharma), avoid harmful intent, control ego and misuse of power, protect society."
                    }
            
            # Step 3: Check high-risk tools
            for tool in self.HIGH_RISK_TOOLS:
                if tool in cmd_lower:
                    guidance = gita_engine.get_ethical_guidance(tool)
                    return {
                        "decision": "warn",
                        "reason": f"High-risk tool '{tool}' requires explicit user justification and strict confirmation (Self-Control teaching)",
                        "risk_level": "high",
                        "intent": intent,
                        "gita_verse": guidance.get("verse"),
                        "gita_message": guidance.get("message"),
                        "action_type": tool,
                        "requires_justification": True
                    }
            
            # Step 4: Check for Dharma (good actions)
            for pattern in self.DHARMA_PATTERNS:
                if pattern in cmd_lower:
                    guidance = gita_engine.get_ethical_guidance("defense" if "protect" in cmd_lower or "defense" in cmd_lower else "learning")
                    return {
                        "decision": "allow",
                        "reason": f"Ethical security action aligned with protection/duty: '{pattern}'",
                        "risk_level": "low",
                        "intent": intent,
                        "gita_verse": guidance.get("verse"),
                        "gita_message": "Performing duty aligned with protection (Dharma).",
                        "action_type": "defense"
                    }
            
            # Step 5: Intent based
            if intent == "malicious":
                guidance = gita_engine.get_ethical_guidance("attack")
                return {
                    "decision": "deny",
                    "reason": "Malicious intent detected - violates Dharma",
                    "risk_level": "high",
                    "intent": intent,
                    "gita_verse": guidance.get("verse"),
                    "gita_message": guidance.get("message")
                }
            elif intent == "suspicious":
                guidance = gita_engine.get_ethical_guidance("attack")
                return {
                    "decision": "warn",
                    "reason": "Suspicious intent - requires additional confirmation and justification",
                    "risk_level": "medium",
                    "intent": intent,
                    "gita_verse": guidance.get("verse"),
                    "gita_message": guidance.get("message")
                }
            else:
                guidance = gita_engine.get_ethical_guidance("defense")
                return {
                    "decision": "allow",
                    "reason": "No ethical violation detected - action appears safe and aligned with learning/protection",
                    "risk_level": "low",
                    "intent": intent,
                    "gita_verse": guidance.get("verse"),
                    "gita_message": guidance.get("message", "Perform your duty with detachment")
                }
                
        except Exception as e:
            ErrorHandler.handle_exception(e, "DharmaEngine.evaluate_action")
            return {
                "decision": "warn",
                "reason": "Error in ethical evaluation - defaulting to cautious allow with warning",
                "risk_level": "medium",
                "error": str(e)
            }

# Global instance
dharma_engine = DharmaEngine()
