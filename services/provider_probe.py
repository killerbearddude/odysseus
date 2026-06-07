"""
Provider probing helpers for Odysseus model integrations.

Provider probes are explicit, mocked in tests, and redacted. The helpers verify
configuration shape, offline-mode behavior, URL safety, and optionally a mocked
model-list call without contacting real providers in CI.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

try:
    from core.offline_mode import is_offline_mode
except Exception:  # pragma: no cover - defensive fallback for partial checkouts.
    def is_offline_mode() -> bool:
        """Return false when the offline helper is unavailable."""
        return os.getenv("ODYSSEUS_OFFLINE_MODE", "false").lower() in {"1", "true", "yes", "on"}


HttpGet = Callable[[str, Mapping[str, str]], Mapping[str, Any]]

EXTERNAL_PROVIDERS = {
    "openai",
    "openrouter",
    "anthropic",
    "gemini",
    "groq",
    "xai",
    "deepseek",
}

LOCAL_PROVIDERS = {"ollama", "llama.cpp", "vllm", "sglang", "lm studio", "local-openai"}

_TOKEN_RE = re.compile(r"(?i)(sk-[a-z0-9_\-]{8,}|bearer\s+[a-z0-9._\-]{8,}|api[_-]?key\s*[=:]\s*\S+)")


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration needed to probe one provider."""

    name: str
    endpoint_url: str | None = None
    api_key: str | None = None
    requires_api_key: bool = True
    local: bool = False
    model_list_path: str = "/v1/models"


@dataclass(frozen=True)
class ProviderProbeResult:
    """Redacted provider probe result."""

    provider: str
    status: str
    message: str
    endpoint_url: str | None = None
    models: list[str] = field(default_factory=list)
    offline_blocked: bool = False
    raw_api_key_logged: bool = False


def redact_provider_text(text: str, api_key: str | None = None) -> str:
    """Redact provider keys and token-like values from probe messages."""
    redacted = text
    if api_key:
        redacted = redacted.replace(api_key, "[REDACTED_API_KEY]")
    redacted = _TOKEN_RE.sub("[REDACTED_SECRET]", redacted)
    return redacted


def _provider_kind(name: str) -> str:
    """Return local/external/unknown provider class from name."""
    normalized = name.strip().lower()
    if normalized in EXTERNAL_PROVIDERS:
        return "external"
    if normalized in LOCAL_PROVIDERS:
        return "local"
    return "unknown"


def _is_safe_local_endpoint(url: str) -> bool:
    """Allow localhost endpoints and reject metadata/internal non-local targets."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    # Keep this conservative for model-serving probes: local provider probes are
    # expected to use localhost unless later policy explicitly expands the set.
    return False


def _join_url(base: str, path: str) -> str:
    """Join an endpoint base URL and provider probe path."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def _extract_models(payload: Mapping[str, Any]) -> list[str]:
    """Extract model ids from common model-list payloads."""
    data = payload.get("data")
    if isinstance(data, list):
        models = []
        for item in data:
            if isinstance(item, Mapping):
                value = item.get("id") or item.get("name")
                if isinstance(value, str):
                    models.append(value)
            elif isinstance(item, str):
                models.append(item)
        return models
    models = payload.get("models")
    if isinstance(models, list):
        return [item for item in models if isinstance(item, str)]
    return []


def probe_provider(
    config: ProviderConfig,
    *,
    http_get: HttpGet | None = None,
    env: Mapping[str, str] | None = None,
) -> ProviderProbeResult:
    """
    Probe provider readiness without leaking secrets.

    Real network calls are only made if the caller supplies `http_get`. Tests use
    mocks; CI must not contact provider APIs.
    """
    env = env or os.environ
    offline = is_offline_mode()
    provider_kind = "local" if config.local else _provider_kind(config.name)

    if provider_kind == "external" and offline:
        return ProviderProbeResult(
            provider=config.name,
            status="blocked",
            message=f"{config.name} probe is disabled while ODYSSEUS_OFFLINE_MODE=true.",
            offline_blocked=True,
        )

    if config.requires_api_key and not config.api_key and provider_kind == "external":
        return ProviderProbeResult(
            provider=config.name,
            status="disabled",
            message=f"{config.name} is not configured: missing API key.",
        )

    if not config.endpoint_url:
        return ProviderProbeResult(
            provider=config.name,
            status="disabled",
            message=f"{config.name} is not configured: missing endpoint URL.",
        )

    parsed = urlparse(config.endpoint_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ProviderProbeResult(
            provider=config.name,
            status="error",
            message="Provider endpoint URL is invalid.",
            endpoint_url=config.endpoint_url,
        )

    if provider_kind == "local" and not _is_safe_local_endpoint(config.endpoint_url):
        return ProviderProbeResult(
            provider=config.name,
            status="error",
            message="Local provider endpoint is not permitted by URL policy.",
            endpoint_url=config.endpoint_url,
        )

    if http_get is None:
        return ProviderProbeResult(
            provider=config.name,
            status="configured",
            message="Provider configuration is present; active probe was not requested.",
            endpoint_url=config.endpoint_url,
        )

    headers: dict[str, str] = {}
    if config.api_key:
        headers["Authorization"] = "Bearer [REDACTED_API_KEY]"

    try:
        payload = http_get(_join_url(config.endpoint_url, config.model_list_path), headers)
    except Exception as exc:
        message = redact_provider_text(str(exc), config.api_key)
        return ProviderProbeResult(
            provider=config.name,
            status="error",
            message=message,
            endpoint_url=config.endpoint_url,
            raw_api_key_logged=bool(config.api_key and config.api_key in message),
        )

    models = _extract_models(payload)
    return ProviderProbeResult(
        provider=config.name,
        status="ready" if models else "reachable",
        message="Provider model-list probe succeeded." if models else "Provider endpoint reached but no models were reported.",
        endpoint_url=config.endpoint_url,
        models=models,
        raw_api_key_logged=False,
    )
