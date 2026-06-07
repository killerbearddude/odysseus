"""
Regression tests for Odysseus startup safety checks.

These tests prevent unsafe deployment configurations from reaching request
serving, especially first-run or disabled-auth modes that could otherwise be
exposed on a LAN or public interface.
"""

import pytest

from core.config import StartupSafetyError, validate_startup_safety


def _env(**overrides):
    """
    Build a safe baseline startup environment for focused validation tests.

    Each test overrides only the variables relevant to the regression being
    checked, which keeps failures easy to diagnose.
    """
    base = {
        "APP_BIND": "127.0.0.1",
        "AUTH_ENABLED": "true",
        "LOCALHOST_BYPASS": "false",
        "ODYSSEUS_DEPLOYMENT_MODE": "local",
        "SECURE_COOKIES": "false",
    }
    base.update(overrides)
    return base


def test_unsafe_external_bind_with_auth_disabled_fails():
    # Prevents an unauthenticated Odysseus instance from binding to every
    # interface, which could expose admin-console functionality to the network.
    with pytest.raises(StartupSafetyError, match="AUTH_ENABLED=false"):
        validate_startup_safety(_env(AUTH_ENABLED="false", APP_BIND="0.0.0.0"))


def test_private_proxy_without_secure_cookies_fails():
    # Prevents private-proxy deployments from starting with cookies that can be
    # sent over cleartext HTTP or mishandled behind HTTPS-terminating proxies.
    with pytest.raises(StartupSafetyError, match="SECURE_COOKIES=true"):
        validate_startup_safety(
            _env(ODYSSEUS_DEPLOYMENT_MODE="private-proxy", SECURE_COOKIES="false")
        )


def test_localhost_bypass_outside_loopback_bind_fails():
    # Prevents localhost bypass from becoming a network-wide auth bypass when
    # the application bind address is reachable beyond the local machine.
    with pytest.raises(StartupSafetyError, match="LOCALHOST_BYPASS=true"):
        validate_startup_safety(
            _env(LOCALHOST_BYPASS="true", APP_BIND="0.0.0.0")
        )


def test_safe_local_loopback_startup_passes():
    # Confirms the simple local developer flow still starts with loopback bind,
    # auth enabled, and no private-proxy cookie requirement.
    assert validate_startup_safety(_env()) is None
