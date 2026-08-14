"""Authorization policy for Red Team operations - Admin unrestricted as per user request to not restrict admin."""

from typing import Dict, Tuple
import ipaddress
import os
import re
import json
from pathlib import Path

from .error_handler import ErrorHandler


class AuthorizationLayer:
    """Restrict active testing to local/private targets by default, but admin unrestricted."""

    FORBIDDEN_KEYWORDS = ("gov.in", ".gov", "bank", "government")

    def _is_admin_user(self, user_token: str = None) -> bool:
        """Check if user is admin - admin unrestricted as per user request"""
        if not user_token:
            # Local CLI is considered operator, but not necessarily admin
            # For CLI, we allow as admin? The review says local CLI is trusted as interactive operator
            # For admin unrestricted, we treat CLI as admin for convenience? No, we check users.json
            return False
        try:
            # Load users.json to check role
            users_file = Path(__file__).resolve().parent.parent / "database" / "users.json"
            if users_file.exists():
                users = json.loads(users_file.read_text(encoding='utf-8'))
                user_data = users.get(user_token, {})
                # Also check if token is username directly
                if user_data.get("role") == "admin":
                    return True
                # Check if user_token is actually username and role admin
                # Also check all users for matching username with admin role
                for uname, udata in users.items():
                    if uname == user_token and udata.get("role") == "admin":
                        return True
        except Exception:
            pass
        return False

    def is_target_allowed(self, target: str, action: str = "", user_token: str = None) -> Tuple[bool, str]:
        try:
            # Admin unrestricted: allow all targets for admin
            if self._is_admin_user(user_token):
                return True, f"Admin unrestricted: target {target} allowed (admin bypass)"

            target = target.strip().lower().rstrip(".")
            if not target:
                return False, "Empty target"
            if any(word in target for word in self.FORBIDDEN_KEYWORDS):
                return False, "Target is explicitly forbidden by policy"
            if target == "localhost":
                return True, "Loopback target"

            try:
                address = ipaddress.ip_address(target)
            except ValueError:
                address = None
            if address is not None:
                if address.is_loopback or address.is_private:
                    return True, "Private/loopback target"
                if os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() == "true":
                    return True, "Public targets enabled by operator policy"
                return False, "Public IP testing is disabled; use an authorized private lab"

            domain = re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", target)
            if domain and "whois" in action.lower():
                return True, "Passive WHOIS lookup allowed"
            if domain and os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() == "true":
                return True, "Public domain testing enabled by operator policy"
            if domain:
                return False, "Public domain testing is disabled; use an authorized private lab"
            return False, "Invalid target format"
        except Exception as exc:
            ErrorHandler.handle_exception(exc, "AuthorizationLayer.is_target_allowed")
            return False, "Target validation failed"

    def is_user_authorized(self, user_token: str = None, action: str = "") -> Tuple[bool, str]:
        return True, "Authenticated operator" if user_token else "Local CLI operator"

    def check_authorization(self, target: str, action: str, user_token: str = None) -> Dict:
        # Admin unrestricted check first
        if self._is_admin_user(user_token):
            return {
                "authorized": True,
                "decision": "allow_with_confirmation" if not action.lower().startswith("whois") else "allow",
                "reason": f"Admin unrestricted: {user_token} allowed for {target} | Admin bypass - no restrictions",
                "requires_confirmation": True,
                "target": target,
                "action": action,
            }

        user_ok, user_reason = self.is_user_authorized(user_token, action)
        target_ok, target_reason = self.is_target_allowed(target, action, user_token=user_token)
        authorized = user_ok and target_ok
        return {
            "authorized": authorized,
            "decision": "allow_with_confirmation" if authorized else "deny",
            "reason": f"{user_reason} | {target_reason}",
            "requires_confirmation": authorized,
            "target": target,
            "action": action,
        }


authorization_layer = AuthorizationLayer()
