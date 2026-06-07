"""
Regression tests for first-admin setup-token safety.

These tests ensure remote or private deployment setup cannot be claimed without
ODYSSEUS_SETUP_TOKEN while preserving the tokenless localhost developer flow.
"""

import pytest
from fastapi import HTTPException

from routes.auth_routes import require_setup_token_if_needed


class _Headers(dict):
    """
    Minimal case-insensitive header mapping for setup-token route tests.

    Starlette headers are case-insensitive. This stub preserves that behavior so
    tests exercise the same header names users and proxies will send.
    """

    def __init__(self, values=None):
        super().__init__()
        for key, value in (values or {}).items():
            self[key.lower()] = value

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)


class _Request:
    """
    Small request stub for require_setup_token_if_needed unit tests.

    The production route receives a FastAPI Request. These tests only need query,
    header, form, and JSON access used by the setup-token guard.
    """

    def __init__(self, *, method="GET", query=None, headers=None, form=None, json=None):
        self.method = method
        self.query_params = query or {}
        self.headers = _Headers(headers)
        self._form = form or {}
        self._json = json or {}

    async def form(self):
        """Return form fields submitted to a setup POST request."""
        return self._form

    async def json(self):
        """Return JSON fields submitted to a setup POST request."""
        return self._json


def _set_private_setup_env(monkeypatch, *, token="setup-secret"):
    """
    Configure an environment where first-admin setup must require a token.

    Private LAN mode is intentionally used because it is remotely reachable by
    design but does not require SECURE_COOKIES like private-proxy mode.
    """
    monkeypatch.setenv("ODYSSEUS_DEPLOYMENT_MODE", "private-lan")
    monkeypatch.setenv("APP_BIND", "0.0.0.0")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("LOCALHOST_BYPASS", "false")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("ODYSSEUS_SETUP_TOKEN", token)


@pytest.mark.asyncio
async def test_local_loopback_setup_works_without_setup_token(monkeypatch):
    # Confirms the current simple localhost first-run setup flow is preserved.
    monkeypatch.setenv("ODYSSEUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("APP_BIND", "127.0.0.1")
    monkeypatch.delenv("ODYSSEUS_SETUP_TOKEN", raising=False)

    assert await require_setup_token_if_needed(_Request()) is None


@pytest.mark.asyncio
async def test_non_loopback_private_setup_fails_without_setup_token(monkeypatch):
    # Prevents remote first-admin account claiming when setup is reachable over a
    # LAN/proxy bind and no token is provided by the requester.
    _set_private_setup_env(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        await require_setup_token_if_needed(_Request())

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_non_loopback_private_setup_succeeds_with_valid_query_token(monkeypatch):
    # Verifies the documented query-string setup-token path works for bootstrap
    # links or manual browser entry during private deployments.
    _set_private_setup_env(monkeypatch)

    request = _Request(query={"setup_token": "setup-secret"})

    assert await require_setup_token_if_needed(request) is None


@pytest.mark.asyncio
async def test_non_loopback_private_setup_succeeds_with_valid_header_token(monkeypatch):
    # Verifies the header setup-token path works for scripted or proxied setup
    # flows that avoid putting the token in URLs.
    _set_private_setup_env(monkeypatch)

    request = _Request(headers={"X-Odysseus-Setup-Token": "setup-secret"})

    assert await require_setup_token_if_needed(request) is None


@pytest.mark.asyncio
async def test_non_loopback_private_setup_succeeds_with_valid_form_token(monkeypatch):
    # Verifies form-based setup can submit the setup token without requiring a
    # separate query parameter or custom header.
    _set_private_setup_env(monkeypatch)

    request = _Request(method="POST", form={"setup_token": "setup-secret"})

    assert await require_setup_token_if_needed(request) is None


@pytest.mark.asyncio
async def test_invalid_setup_token_is_denied(monkeypatch):
    # Prevents an incorrect setup token from being treated as sufficient for
    # remotely reachable first-admin setup.
    _set_private_setup_env(monkeypatch)

    request = _Request(query={"setup_token": "wrong-token"})

    with pytest.raises(HTTPException) as exc:
        await require_setup_token_if_needed(request)

    assert exc.value.status_code == 403
