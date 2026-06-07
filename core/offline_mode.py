"""
Offline-mode helpers for Odysseus local-only enforcement.

This module centralizes checks that prevent optional external integrations from
making network calls when the operator has requested local-only behavior. The
environment variable is read at call time so tests and deployment wrappers can
toggle offline behavior without relying on import order.
"""

from __future__ import annotations

import os
from ipaddress import ip_address
from urllib.parse import urlparse


class OfflineModeError(RuntimeError):
    """Raised when an external-capable feature is blocked by offline mode."""


LOCAL_PROVIDER_NAMES = {
    "local",
    "local-openai",
    "local-openai-compatible",
    "openai-compatible-local",
    "ollama",
    "llama.cpp",
    "llamacpp",
    "lmstudio",
    "lm-studio",
}

EXTERNAL_PROVIDER_NAMES = {
    "anthropic",
    "gemini",
    "google",
    "huggingface",
    "hugging_face",
    "openai",
    "openrouter",
}


def is_offline_mode() -> bool:
    """
    Return whether Odysseus should block external-capable integrations.

    Returns:
        True when ``ODYSSEUS_OFFLINE_MODE`` is one of ``1``, ``true``, ``yes``,
        or ``on`` case-insensitively.
    """
    return os.getenv("ODYSSEUS_OFFLINE_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}


def require_online_feature(feature_name: str) -> None:
    """
    Fail closed when an external-capable feature is used in offline mode.

    Args:
        feature_name: Human-readable feature name for logs and user-facing error
            messages.

    Raises:
        OfflineModeError: If offline mode is enabled.
    """
    if is_offline_mode():
        raise OfflineModeError(f"{feature_name} is disabled while ODYSSEUS_OFFLINE_MODE=true")


def _normalize_provider_name(provider_name: str) -> str:
    """Normalize provider names so equivalent spellings share policy."""
    return provider_name.strip().lower().replace(" ", "-")


def is_local_endpoint(endpoint_url: str | None) -> bool:
    """
    Return whether an endpoint URL points to a local/LAN model service.

    Args:
        endpoint_url: Provider endpoint URL, for example an Ollama or local
            OpenAI-compatible base URL.

    Returns:
        True for localhost, loopback, link-local, RFC1918 private IPv4, and
        unique-local/link-local IPv6 endpoints.
    """
    if not endpoint_url:
        return False

    parsed = urlparse(endpoint_url)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    if host in {"localhost", "host.docker.internal"}:
        return True

    try:
        address = ip_address(host.strip("[]"))
    except ValueError:
        return False

    return bool(address.is_loopback or address.is_private or address.is_link_local)


def require_provider_allowed(provider_name: str, *, endpoint_url: str | None = None) -> None:
    """
    Enforce offline-mode provider rules at the provider boundary.

    Local providers remain usable in offline mode when they are explicitly
    configured with a local endpoint. External hosted providers are blocked.

    Args:
        provider_name: Provider identifier such as ``openai`` or ``ollama``.
        endpoint_url: Optional configured provider base URL.

    Raises:
        OfflineModeError: If offline mode blocks the requested provider.
    """
    if not is_offline_mode():
        return

    normalized = _normalize_provider_name(provider_name)
    if normalized in LOCAL_PROVIDER_NAMES and is_local_endpoint(endpoint_url):
        return

    if normalized in {"openai-compatible", "custom", "custom-openai"} and is_local_endpoint(endpoint_url):
        return

    if normalized in EXTERNAL_PROVIDER_NAMES or not is_local_endpoint(endpoint_url):
        raise OfflineModeError(
            f"provider '{provider_name}' is disabled while ODYSSEUS_OFFLINE_MODE=true; "
            "configure a local provider endpoint to use models offline"
        )


def require_web_research_allowed() -> None:
    """
    Enforce offline-mode rules for web research and search features.

    Raises:
        OfflineModeError: If offline mode is enabled.
    """
    require_online_feature("web research/search")


def require_model_download_allowed(source_name: str = "model download") -> None:
    """
    Enforce offline-mode rules for model downloads and Hugging Face access.

    Args:
        source_name: Human-readable source name for a user-facing error.

    Raises:
        OfflineModeError: If offline mode is enabled.
    """
    require_online_feature(source_name)


def require_external_asset_allowed(asset_url: str) -> None:
    """
    Enforce offline-mode rules for external image, script, CSS, or CDN assets.

    Args:
        asset_url: External asset URL that would be loaded by the browser/server.

    Raises:
        OfflineModeError: If offline mode is enabled.
    """
    if is_offline_mode() and asset_url.lower().startswith(("http://", "https://")):
        raise OfflineModeError("external asset loads are disabled while ODYSSEUS_OFFLINE_MODE=true")


def offline_status() -> dict[str, object]:
    """
    Return diagnostics-friendly offline-mode status.

    Returns:
        Small JSON-serializable status payload suitable for health/config status
        endpoints without exposing secrets or provider credentials.
    """
    offline = is_offline_mode()
    return {
        "offline_mode": offline,
        "external_providers_allowed": not offline,
        "web_research_allowed": not offline,
        "model_downloads_allowed": not offline,
        "external_assets_allowed": not offline,
    }
