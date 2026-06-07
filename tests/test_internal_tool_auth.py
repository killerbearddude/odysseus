"""
Regression tests for internal-tool admin authorization.

The internal-tool token is powerful because it lets in-process agent tooling call
admin-gated routes over loopback. These tests ensure the raw header never grants
admin access unless AuthMiddleware has already validated the direct-loopback
trust boundary and stamped request state accordingly.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core import middleware


def _auth_manager(*, configured=True, admin_users=frozenset()):
    """
    Build a minimal auth manager stub for require_admin unit tests.

    The production auth manager has more behavior, but these tests only need the
    configured flag and admin lookup used by the admin gate.
    """
    return SimpleNamespace(
        is_configured=configured,
        is_admin=lambda username: username in admin_users,
    )


def _request(
    *,
    current_user=None,
    internal_tool_validated=False,
    headers=None,
    admin_users=frozenset(),
):
    """
    Build a minimal request-like object for the authorization helper.

    Using a small stub keeps these tests focused on require_admin behavior
    instead of booting the full FastAPI app.
    """
    return SimpleNamespace(
        headers=headers or {},
        state=SimpleNamespace(
            current_user=current_user,
            internal_tool_validated=internal_tool_validated,
        ),
        app=SimpleNamespace(
            state=SimpleNamespace(
                auth_manager=_auth_manager(admin_users=admin_users),
            )
        ),
    )


def test_raw_internal_token_header_does_not_grant_admin(monkeypatch):
    # Prevents regression where require_admin trusted X-Odysseus-Internal-Token
    # directly, bypassing app.py's loopback/proxy validation. The token constant
    # is patched to a non-empty value so the old vulnerable branch would pass.
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setattr(middleware, "INTERNAL_TOOL_TOKEN", "unit-test-token")

    req = _request(
        headers={middleware.INTERNAL_TOOL_HEADER: "unit-test-token"},
    )

    with pytest.raises(HTTPException) as exc:
        middleware.require_admin(req)

    assert exc.value.status_code == 403


def test_internal_tool_username_without_validation_flag_does_not_grant_admin(
    monkeypatch,
):
    # Prevents a forged or stale request.state.current_user value from becoming
    # admin-equivalent without middleware validation.
    monkeypatch.setenv("AUTH_ENABLED", "true")

    req = _request(current_user="internal-tool", internal_tool_validated=False)

    with pytest.raises(HTTPException) as exc:
        middleware.require_admin(req)

    assert exc.value.status_code == 403


def test_validated_internal_tool_sentinel_grants_admin(monkeypatch):
    # Confirms the intended in-process tool path still works after removing the
    # raw-header bypass.
    monkeypatch.setenv("AUTH_ENABLED", "true")

    req = _request(current_user="internal-tool", internal_tool_validated=True)

    assert middleware.require_admin(req) is None


def test_regular_admin_user_still_grants_admin(monkeypatch):
    # Confirms the normal browser-session admin path is preserved.
    monkeypatch.setenv("AUTH_ENABLED", "true")

    req = _request(current_user="alice", admin_users=frozenset({"alice"}))

    assert middleware.require_admin(req) is None


def test_non_admin_user_is_denied(monkeypatch):
    # Confirms this refactor does not weaken the ordinary user/admin boundary.
    monkeypatch.setenv("AUTH_ENABLED", "true")

    req = _request(current_user="bob", admin_users=frozenset({"alice"}))

    with pytest.raises(HTTPException) as exc:
        middleware.require_admin(req)

    assert exc.value.status_code == 403
