"""
Centralized authorization helpers for Odysseus route handlers.

This module owns shared admin-gate decisions for HTTP route handlers. It does
not validate raw internal-tool headers; only AuthMiddleware can safely do that
because it also evaluates the direct-loopback trust boundary for the request.
"""

import os

from fastapi import HTTPException, Request


# Canonical pseudo-user stamped by AuthMiddleware after validating both the
# internal-tool token and the direct-loopback request origin.
INTERNAL_TOOL_USERNAME = "internal-tool"


def is_validated_internal_tool_admin(request: Request) -> bool:
    """
    Return True only for the canonical validated internal-tool admin request.

    AuthMiddleware is responsible for setting ``internal_tool_validated`` after
    it validates both the token value and the direct-loopback origin. This helper
    deliberately ignores request headers so a raw token cannot bypass the
    middleware's proxy/tunnel and loopback checks.
    """
    return (
        getattr(request.state, "internal_tool_validated", False) is True
        and getattr(request.state, "current_user", None) == INTERNAL_TOOL_USERNAME
    )


def require_admin(request: Request) -> None:
    """
    Require the current request to be admin-authorized.

    Admin access is granted when authentication is explicitly disabled, when
    AuthMiddleware has stamped a validated internal-tool request, or when the
    configured auth manager confirms the current session user is an admin.

    Raises:
        HTTPException: 403 when the request is not admin-authorized.
    """
    if os.getenv("AUTH_ENABLED", "true").lower() == "false":
        return

    if is_validated_internal_tool_admin(request):
        return

    auth_mgr = getattr(request.app.state, "auth_manager", None)
    if not auth_mgr or not auth_mgr.is_configured:
        raise HTTPException(403, "Admin only")

    user = getattr(request.state, "current_user", None)
    if not user or not auth_mgr.is_admin(user):
        raise HTTPException(403, "Admin only")
