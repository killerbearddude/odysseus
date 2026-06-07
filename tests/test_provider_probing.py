from __future__ import annotations

from services.provider_probe import ProviderConfig, probe_provider


def test_unconfigured_provider_reports_disabled():
    # Regression guard: absent keys must disable providers rather than causing late auth failures.
    result = probe_provider(ProviderConfig(name="OpenAI", endpoint_url="https://api.openai.example"))

    assert result.status == "disabled"
    assert "missing api key" in result.message.lower()


def test_configured_provider_with_invalid_url_reports_clear_error():
    # Regression guard: invalid endpoints should produce a user-visible configuration error.
    result = probe_provider(ProviderConfig(name="OpenAI", endpoint_url="not a url", api_key="sk-test-secret"))

    assert result.status == "error"
    assert "invalid" in result.message.lower()


def test_mock_provider_model_list_success_reports_ready():
    # Regression guard: readiness should be based on a provider response, not key presence alone.
    def fake_get(url, headers):
        assert url.endswith("/v1/models")
        assert headers["Authorization"] == "Bearer [REDACTED_API_KEY]"
        return {"data": [{"id": "model-a"}]}

    result = probe_provider(
        ProviderConfig(name="OpenAI", endpoint_url="https://api.openai.example", api_key="sk-test-secret"),
        http_get=fake_get,
    )

    assert result.status == "ready"
    assert result.models == ["model-a"]
    assert result.raw_api_key_logged is False


def test_mock_provider_auth_failure_redacts_token():
    # Regression guard: provider probe errors must not expose API keys.
    token = "sk-test-secret-value"

    def fake_get(url, headers):
        raise RuntimeError(f"401 bad key {token}")

    result = probe_provider(
        ProviderConfig(name="OpenAI", endpoint_url="https://api.openai.example", api_key=token),
        http_get=fake_get,
    )

    assert result.status == "error"
    assert token not in result.message
    assert "redacted" in result.message.lower()


def test_offline_mode_blocks_external_provider_probes(monkeypatch):
    # Regression guard: offline mode blocks external probes before network clients are invoked.
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "true")
    called = False

    def fake_get(url, headers):
        nonlocal called
        called = True
        return {"data": []}

    result = probe_provider(
        ProviderConfig(name="OpenAI", endpoint_url="https://api.openai.example", api_key="sk-test"),
        http_get=fake_get,
    )

    assert result.status == "blocked"
    assert result.offline_blocked is True
    assert called is False


def test_local_ollama_probe_uses_local_endpoint_policy():
    # Regression guard: local providers are allowed only through explicitly local endpoints.
    result = probe_provider(
        ProviderConfig(name="Ollama", endpoint_url="http://127.0.0.1:11434", requires_api_key=False, local=True),
        http_get=lambda url, headers: {"models": ["llama3"]},
    )

    assert result.status == "ready"
    assert result.models == ["llama3"]


def test_local_openai_compatible_endpoint_is_blocked_if_url_is_unsafe():
    # Regression guard: local endpoint mode must not become SSRF to metadata/internal addresses.
    result = probe_provider(
        ProviderConfig(
            name="local-openai",
            endpoint_url="http://169.254.169.254/latest/meta-data",
            requires_api_key=False,
            local=True,
        )
    )

    assert result.status == "error"
    assert "url policy" in result.message.lower()


def test_provider_probe_never_logs_raw_api_key():
    # Regression guard: even successful probe metadata must not contain provider keys.
    token = "sk-test-secret-value"
    result = probe_provider(
        ProviderConfig(name="OpenAI", endpoint_url="https://api.openai.example", api_key=token),
        http_get=lambda url, headers: {"data": [{"id": "model-a"}]},
    )

    encoded = repr(result)
    assert token not in encoded
