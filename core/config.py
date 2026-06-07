"""
Deployment-safety configuration helpers for Odysseus.

This module centralizes startup and first-run setup checks that must be shared
by the application entry point, setup routes, and security tests. It reads from
process environment variables at call time so tests can use monkeypatch without
reloading the module.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Mapping


# PR2_DEPLOYMENT_SAFETY_HELPERS
# Deployment modes are intentionally explicit so public-facing documentation,
# startup validation, and first-run setup behavior use the same vocabulary.
DEPLOYMENT_MODES = frozenset(
    {"local", "private-lan", "private-proxy", "offline", "development"}
)


class StartupSafetyError(RuntimeError):
    """
    Raised when environment settings would expose Odysseus unsafely.

    Startup validation raises this before the ASGI app begins serving requests,
    which prevents accidental first-run exposure with unsafe auth or cookie
    settings.
    """


@dataclass(frozen=True)
class DeploymentSafetySettings:
    """
    Normalized deployment-safety settings derived from environment variables.

    The values here intentionally model only startup and first-run setup safety.
    Broader offline-mode enforcement, provider policy, and tool sandboxing remain
    separate roadmap items.
    """

    deployment_mode: str
    app_bind: str
    auth_enabled: bool
    localhost_bypass: bool
    secure_cookies: bool
    setup_token: str

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None
    ) -> "DeploymentSafetySettings":
        """
        Build normalized settings from an environment mapping.

        Args:
            env: Optional mapping to read instead of ``os.environ``. Tests pass a
                small dict here to avoid mutating process-wide state.

        Returns:
            DeploymentSafetySettings populated with normalized values.
        """
        source = os.environ if env is None else env
        deployment_mode = source.get("ODYSSEUS_DEPLOYMENT_MODE", "local").strip().lower()
        app_bind = source.get("APP_BIND", "127.0.0.1").strip() or "127.0.0.1"
        return cls(
            deployment_mode=deployment_mode,
            app_bind=app_bind,
            auth_enabled=_env_bool(source.get("AUTH_ENABLED", "true"), default=True),
            localhost_bypass=_env_bool(
                source.get("LOCALHOST_BYPASS", "false"), default=False
            ),
            secure_cookies=_env_bool(source.get("SECURE_COOKIES", "false"), default=False),
            setup_token=source.get("ODYSSEUS_SETUP_TOKEN", ""),
        )


def _env_bool(value: str | None, *, default: bool) -> bool:
    """
    Parse common environment-style booleans.

    Args:
        value: Raw environment value.
        default: Value to return when the variable is unset or empty.

    Returns:
        Boolean interpretation of the environment value.
    """
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_host(host: str) -> str:
    """
    Normalize bind host values for safety comparisons.

    Uvicorn and Docker examples often use bracketed IPv6 hosts or uppercase
    localhost values. This helper keeps validation conservative while accepting
    the obvious loopback spellings used in local development.
    """
    return host.strip().lower().strip("[]")


def is_loopback_bind(host: str) -> bool:
    """
    Return True when the bind host is strictly loopback-only.

    A loopback-only bind keeps first-run setup on the local machine and preserves
    the current simple developer flow. Wildcard and LAN binds are treated as
    remotely reachable and therefore require stronger setup protection.
    """
    return _normalize_host(host) in {"127.0.0.1", "localhost", "::1"}


def is_wildcard_bind(host: str) -> bool:
    """
    Return True when the bind host listens on all interfaces.

    Wildcard binds are the most dangerous startup shape because they can expose
    first-run setup or disabled-auth instances to an entire LAN or the public
    internet depending on firewall and proxy configuration.
    """
    return _normalize_host(host) in {"0.0.0.0", "::", "*"}


def validate_startup_safety(env: Mapping[str, str] | None = None) -> None:
    """
    Fail closed when startup settings would expose Odysseus unsafely.

    Args:
        env: Optional environment mapping for tests.

    Raises:
        StartupSafetyError: If one or more unsafe combinations are detected.
    """
    settings = DeploymentSafetySettings.from_env(env)
    errors: list[str] = []

    if settings.deployment_mode not in DEPLOYMENT_MODES:
        errors.append(
            "ODYSSEUS_DEPLOYMENT_MODE must be one of: "
            + ", ".join(sorted(DEPLOYMENT_MODES))
        )

    if not settings.auth_enabled and is_wildcard_bind(settings.app_bind):
        errors.append("AUTH_ENABLED=false is forbidden when APP_BIND listens on all interfaces")

    if settings.localhost_bypass and not is_loopback_bind(settings.app_bind):
        errors.append(
            "LOCALHOST_BYPASS=true is only allowed with APP_BIND=127.0.0.1, "
            "localhost, or ::1"
        )

    if settings.deployment_mode == "private-proxy" and not settings.secure_cookies:
        errors.append(
            "ODYSSEUS_DEPLOYMENT_MODE=private-proxy requires SECURE_COOKIES=true"
        )

    if errors:
        message = "Unsafe Odysseus startup configuration:\n- " + "\n- ".join(errors)
        raise StartupSafetyError(message)


def setup_token_required(env: Mapping[str, str] | None = None) -> bool:
    """
    Return True when first-admin setup must require ODYSSEUS_SETUP_TOKEN.

    Tokenless setup is intentionally preserved only for strictly loopback local
    development. Private LAN, private proxy, offline-with-external-bind, and any
    other non-loopback bind are considered remotely reachable for setup safety.
    """
    settings = DeploymentSafetySettings.from_env(env)
    if settings.deployment_mode in {"private-lan", "private-proxy"}:
        return True
    return not is_loopback_bind(settings.app_bind)


def is_valid_setup_token(
    provided_token: str | None, env: Mapping[str, str] | None = None
) -> bool:
    """
    Validate a first-run setup token using constant-time comparison.

    Args:
        provided_token: Token submitted by query string, header, or POST body.
        env: Optional environment mapping for tests.

    Returns:
        True when setup is tokenless loopback setup, or when a required token is
        configured and matches the submitted value.
    """
    if not setup_token_required(env):
        return True

    settings = DeploymentSafetySettings.from_env(env)
    expected = settings.setup_token
    if not expected or not provided_token:
        return False

    return secrets.compare_digest(str(provided_token), expected)
