"""
Security tests for ODYSSEUS_OFFLINE_MODE local-only enforcement.

These tests keep external-capable integrations fail-closed when the operator has
requested offline/local-only behavior. They use helper boundaries and do not call
real model providers, perform searches, or download models.
"""

from __future__ import annotations

import pytest

from core.offline_mode import (
    OfflineModeError,
    is_offline_mode,
    offline_status,
    require_external_asset_allowed,
    require_model_download_allowed,
    require_online_feature,
    require_provider_allowed,
    require_web_research_allowed,
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch):
    """Run every test in this module with explicit offline mode enabled."""
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "true")


def test_offline_mode_flag_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch):
    # Prevents stale import-time settings from allowing external integrations.
    assert is_offline_mode() is True
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "false")
    assert is_offline_mode() is False


def test_external_model_providers_are_blocked_in_offline_mode():
    # Hosted providers must not be reachable when the operator requests local-only behavior.
    for provider in ("openai", "openrouter", "anthropic", "gemini"):
        with pytest.raises(OfflineModeError, match="ODYSSEUS_OFFLINE_MODE=true"):
            require_provider_allowed(provider, endpoint_url="https://api.example.invalid/v1")


def test_local_provider_endpoint_remains_allowed_in_offline_mode():
    # Local providers such as Ollama remain usable because they do not require external egress.
    require_provider_allowed("ollama", endpoint_url="http://127.0.0.1:11434")
    require_provider_allowed("openai-compatible", endpoint_url="http://localhost:8080/v1")


def test_web_research_and_search_are_blocked():
    # Web research/search is explicitly external-capable and must fail closed offline.
    with pytest.raises(OfflineModeError, match="web research/search"):
        require_web_research_allowed()


def test_model_downloads_and_hugging_face_access_are_blocked():
    # Model downloads can reach Hugging Face or other registries and must stop at the boundary.
    with pytest.raises(OfflineModeError, match="Hugging Face model download"):
        require_model_download_allowed("Hugging Face model download")


def test_external_assets_are_blocked_with_clear_error():
    # Offline mode should prevent CDN/script/image loads and return a clear operator-facing error.
    with pytest.raises(OfflineModeError, match="external asset loads"):
        require_external_asset_allowed("https://cdn.jsdelivr.net/npm/example.js")


def test_online_feature_error_message_is_user_visible():
    # Errors should be clear without leaking credentials or internal provider config.
    with pytest.raises(OfflineModeError) as exc:
        require_online_feature("provider probe")
    message = str(exc.value)
    assert "provider probe" in message
    assert "ODYSSEUS_OFFLINE_MODE=true" in message
    assert "sk-" not in message


def test_offline_status_reports_local_only_mode():
    # Diagnostics/health-style status should expose the effective offline flag.
    status = offline_status()
    assert status["offline_mode"] is True
    assert status["external_providers_allowed"] is False
    assert status["web_research_allowed"] is False
    assert status["model_downloads_allowed"] is False
