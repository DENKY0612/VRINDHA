"""
Safety & Authorization Layer - Combines Dharma, Authorization, Intent
Final safety net before execution
"""
from typing import Dict
from .dharma_engine import dharma_engine
from .authorization import authorization_layer
from .intent_analyzer import intent_analyzer
from .error_handler import ErrorHandler

class SafetyLayer:
    """Unified safety checks"""
    
    def evaluate_request(self, command: str, target: str = "", mode: str = "unknown") -> Dict:
        try:
            # 1. Intent
            intent = intent_analyzer.analyze(command)
            # 2. Dharma
            dharma = dharma_engine.evaluate_action(command, intent)
            # 3. Authorization (if target extracted)
            auth = authorization_layer.check_authorization(target if target else command, command) if mode == "red" else {"authorized": True, "decision": "allow", "reason": "Blue Team automated allowed"}
            
            # Overall decision logic
            if dharma.get("decision") == "deny" or not auth.get("authorized", True):
                return {
                    "safe": False,
                    "decision": "deny",
                    "reason": f"Dharma: {dharma.get('reason')} | Auth: {auth.get('reason')}",
                    "dharma": dharma,
                    "intent": intent,
                    "auth": auth,
                    "requires_confirmation": False
                }
            
            if dharma.get("decision") == "warn" or auth.get("requires_confirmation"):
                return {
                    "safe": True,
                    "decision": "warn",
                    "reason": f"Requires confirmation: {dharma.get('reason')} | {auth.get('reason')}",
                    "dharma": dharma,
                    "intent": intent,
                    "auth": auth,
                    "requires_confirmation": True
                }
            
            return {
                "safe": True,
                "decision": "allow",
                "reason": "All safety checks passed",
                "dharma": dharma,
                "intent": intent,
                "auth": auth,
                "requires_confirmation": False if mode == "blue" else True  # Red always confirmation per blueprint
            }
        except Exception as e:
            ErrorHandler.handle_exception(e, "SafetyLayer.evaluate_request")
            return {"safe": False, "decision": "deny", "reason": f"Safety evaluation error: {e}", "requires_confirmation": False}

safety_layer = SafetyLayer()
