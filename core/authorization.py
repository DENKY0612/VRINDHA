"""Authorization policy for Red Team operations."""
from typing import Dict, Tuple
import ipaddress
import os
import re

from .error_handler import ErrorHandler


class AuthorizationLayer:
    """Restrict active testing to local/private targets by default."""

    FORBIDDEN_KEYWORDS = ("gov.in", ".gov", "bank", "government")

    def is_target_allowed(self, target: str, action: str = "") -> Tuple[bool, str]:
        try:
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
        # API authentication supplies the username as user_token. The local CLI
        # is trusted as an interactive operator but still requires confirmation.
        return True, "Authenticated operator" if user_token else "Local CLI operator"

    def check_authorization(self, target: str, action: str, user_token: str = None) -> Dict:
        user_ok, user_reason = self.is_user_authorized(user_token, action)
        target_ok, target_reason = self.is_target_allowed(target, action)
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
