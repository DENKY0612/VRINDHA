"""
Safety & Authorization Layer - Combines Dharma, Authorization, Intent
Final safety net before execution - Admin unrestricted as per user request
"""

from typing import Dict
import json
from pathlib import Path
from .dharma_engine import dharma_engine
from .authorization import authorization_layer
from .intent_analyzer import intent_analyzer
from .error_handler import ErrorHandler

class SafetyLayer:
    """Unified safety checks - Admin unrestricted"""

    def _is_admin_user(self, user_token: str = None) -> bool:
        if not user_token:
            return False
        try:
            users_file = Path(__file__).resolve().parent.parent / "database" / "users.json"
            if users_file.exists():
                users = json.loads(users_file.read_text(encoding='utf-8'))
                user_data = users.get(user_token, {})
                if user_data.get("role") == "admin":
                    return True
                for uname, udata in users.items():
                    if uname == user_token and udata.get("role") == "admin":
                        return True
        except Exception:
            pass
        return False

    def evaluate_request(self, command: str, target: str = "", mode: str = "unknown", user_token: str = None) -> Dict:
        try:
            # Admin unrestricted: bypass all safety checks as per user request to not restrict admin
            if self._is_admin_user(user_token):
                intent = intent_analyzer.analyze(command)
                dharma = dharma_engine.evaluate_action(command, intent)
                return {
                    "safe": True,
                    "decision": "allow",
                    "reason": f"Admin unrestricted: bypass safety - {user_token} allowed for {command[:50]}",
                    "dharma": dharma,
                    "intent": intent,
                    "auth": {"authorized": True, "decision": "allow", "reason": "Admin unrestricted"},
                    "requires_confirmation": False
                }

            # 1. Intent
            intent = intent_analyzer.analyze(command)
            # 2. Dharma
            dharma = dharma_engine.evaluate_action(command, intent)
            # 3. Authorization (if target extracted) - pass user_token for admin check
            auth = authorization_layer.check_authorization(target if target else command, command, user_token=user_token) if mode == "red" else {"authorized": True, "decision": "allow", "reason": "Blue Team automated allowed"}
            
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
                "requires_confirmation": False if mode == "blue" else True
            }
        except Exception as e:
            ErrorHandler.handle_exception(e, "SafetyLayer.evaluate_request")
            return {"safe": False, "decision": "deny", "reason": f"Safety evaluation error: {e}", "requires_confirmation": False}

safety_layer = SafetyLayer()
