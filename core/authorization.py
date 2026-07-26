"""
Authorization Layer - Per MASTER BLUEPRINT
Before executing any Red Team action: Check authorization, target allowed, ask confirmation
Never bypass
"""
from typing import Dict, Tuple
import ipaddress
import re
from .error_handler import ErrorHandler

class AuthorizationLayer:
    """Handles authorization for offensive/defensive actions"""
    
    # Allowed targets for safe testing (can be expanded)
    # For MVP: localhost and private ranges are allowed, everything else requires explicit confirmation
    SAFE_TARGETS = ["127.0.0.1", "localhost", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "::1"]
    
    # Forbidden targets (example - never allow)
    FORBIDDEN_KEYWORDS = ["gov.in", ".gov", "bank", "government"]  # simplistic
    
    def is_target_allowed(self, target: str) -> Tuple[bool, str]:
        """Check if target is allowed"""
        try:
            if not target:
                return False, "Empty target"
            
            target_lower = target.lower()
            
            # Check forbidden
            for forb in self.FORBIDDEN_KEYWORDS:
                if forb in target_lower:
                    return False, f"Target contains forbidden keyword '{forb}' - unauthorized"
            
            # If localhost or private IP, allow with warning for confirmation flow
            for safe in self.SAFE_TARGETS:
                if target_lower.startswith(safe) or safe in target_lower:
                    return True, "Target is in safe local range - allowed with confirmation"
            
            # Try to parse as IP
            try:
                ip = ipaddress.ip_address(target)
                if ip.is_private or ip.is_loopback:
                    return True, "Private/Loopback IP - allowed with confirmation"
                # Public IP - requires explicit authorization
                return True, "Public IP detected - requires explicit user authorization and confirmation (high risk)"
            except:
                pass
            
            # Domain - if it's user's own claimed domain? For MVP allow but warn
            # Regex for domain
            domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
            if re.match(domain_pattern, target):
                return True, "Domain target - requires confirmation that you own / have permission to test this domain"
            
            return True, "Target format unknown - proceed with caution and confirmation"
        except Exception as e:
            ErrorHandler.handle_exception(e, "AuthorizationLayer.is_target_allowed")
            return False, f"Error validating target: {e}"
    
    def is_user_authorized(self, user_token: str = None, action: str = "") -> Tuple[bool, str]:
        """
        Check if user is authorized
        For MVP: If no auth system, assume CLI user is authorized but still require confirmation for Red Team
        In API mode, JWT token validation happens elsewhere
        """
        # Future: integrate with JWT / auth module
        # For now: always true for CLI, but log
        return True, "User authorized (CLI mode - for API mode JWT validation required)"
    
    def check_authorization(self, target: str, action: str, user_token: str = None) -> Dict:
        """Full authorization check per blueprint"""
        try:
            user_auth, user_msg = self.is_user_authorized(user_token, action)
            if not user_auth:
                return {
                    "authorized": False,
                    "decision": "deny",
                    "reason": f"User not authorized: {user_msg}",
                    "requires_confirmation": False
                }
            
            target_allowed, target_msg = self.is_target_allowed(target)
            if not target_allowed:
                return {
                    "authorized": False,
                    "decision": "deny",
                    "reason": f"Target not allowed: {target_msg}",
                    "requires_confirmation": False
                }
            
            # If target is allowed but public/high risk, require explicit confirmation
            requires_confirmation = True  # Red Team always requires confirmation per blueprint
            if "Public IP" in target_msg or "Domain target" in target_msg:
                requires_confirmation = True
            
            return {
                "authorized": True,
                "decision": "allow_with_confirmation" if requires_confirmation else "allow",
                "reason": f"{user_msg} | {target_msg}",
                "requires_confirmation": requires_confirmation,
                "target": target,
                "action": action
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "AuthorizationLayer.check_authorization")
            return {
                "authorized": False,
                "decision": "deny",
                "reason": f"Authorization error: {e}",
                "requires_confirmation": False
            }

authorization_layer = AuthorizationLayer()
