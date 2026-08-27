"""Shared FastAPI dependencies for the Vrindha SOC API.

``get_current_user`` / ``get_current_admin`` / ``bearer_scheme`` previously
lived in ``api.main``. They were moved here so the coordination router (and
future routers) can depend on them without importing the whole application
module. ``api.main`` re-exports all three names, so existing imports keep
working.
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .auth import auth_module


# OpenAPI Bearer security scheme; FastAPI exposes the Authorize control in
# Swagger UI because protected endpoints depend on this scheme.
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="JWT returned by POST /login or first-user POST /register",
)


def _active_auth_module():
    """The auth module the application is currently using.

    Read from ``api.main`` at call time (lazy import avoids a circular
    import) so that test harnesses swapping ``api_main.auth_module`` — the
    pattern the existing registration/teams tests use — keep working
    unchanged.
    """
    from . import main as api_main

    return api_main.auth_module


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict:
    """Validate the Bearer JWT and return its claims plus the live user role.

    Tokens are rejected when the account was disabled or removed, so disabling
    a user also revokes their existing tokens.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer authentication required", headers={"WWW-Authenticate": "Bearer"})
    module = _active_auth_module()
    payload = module.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = module.load_users().get(payload.get("sub", ""))
    if not user or not user.get("active", True):
        raise HTTPException(status_code=401, detail="Account is disabled or no longer exists", headers={"WWW-Authenticate": "Bearer"})
    return {**payload, "role": user.get("role", payload.get("role", "user"))}


def get_current_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
