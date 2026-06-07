from __future__ import annotations

from pathlib import Path

import pytest

from services.model_serving_contract import (
    MODEL_DOWNLOAD_TOOL,
    MODEL_SERVE_TOOL,
    ModelActionPolicyGate,
    ModelServingContractError,
    build_model_job_failure_report,
    ensure_model_cache_path,
    local_model_serving_allowed,
    redact_model_log,
    require_external_model_action_allowed,
    require_model_action_policy,
)


def test_model_download_action_requires_policy_gate():
    # Regression guard: model downloads must not bypass the central tool-policy decision.
    with pytest.raises(ModelServingContractError):
        require_model_action_policy(MODEL_DOWNLOAD_TOOL, None)

    require_model_action_policy(
        MODEL_DOWNLOAD_TOOL,
        ModelActionPolicyGate(tool_name=MODEL_DOWNLOAD_TOOL, decision="allow"),
    )


def test_model_serve_action_requires_policy_gate():
    # Regression guard: model serving starts processes and must require policy approval.
    with pytest.raises(ModelServingContractError):
        require_model_action_policy(MODEL_SERVE_TOOL, ModelActionPolicyGate(tool_name=MODEL_SERVE_TOOL, decision="deny"))


def test_model_cache_path_must_be_under_approved_root(tmp_path: Path):
    # Regression guard: model caches must not escape approved storage roots.
    root = tmp_path / "models"
    allowed = root / "llama"
    outside = tmp_path / "outside"

    assert ensure_model_cache_path(allowed, roots=(root,)) == allowed.resolve(strict=False)
    with pytest.raises(ModelServingContractError):
        ensure_model_cache_path(outside, roots=(root,))


def test_model_serving_logs_redact_secrets():
    # Regression guard: failed model jobs must not leak provider keys or token-like values.
    raw = "OPENAI_API_KEY=sk-test-secret-value failed"

    redacted = redact_model_log(raw)

    assert "sk-test-secret-value" not in redacted


def test_offline_mode_blocks_external_model_downloads(monkeypatch):
    # Regression guard: offline mode blocks external model downloads at the contract layer.
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "true")

    with pytest.raises(Exception, match="ODYSSEUS_OFFLINE_MODE"):
        require_external_model_action_allowed("Hugging Face model download")


def test_local_model_serving_remains_allowed_when_policy_allows():
    # Regression guard: local serving should still be possible after explicit policy approval.
    gate = ModelActionPolicyGate(tool_name=MODEL_SERVE_TOOL, decision="allow")

    assert local_model_serving_allowed(gate) is True


def test_failed_job_report_is_actionable_and_redacted(tmp_path: Path):
    # Regression guard: failed jobs should expose bounded diagnostics without raw secrets.
    report = build_model_job_failure_report(
        command=["python", "serve.py"],
        working_directory=tmp_path,
        exit_code=127,
        stdout="starting",
        stderr="command not found; OPENAI_API_KEY=sk-test-secret-value",
        log_path=tmp_path / "serve.log",
    )

    assert report.exit_code == 127
    assert "command" in report.likely_cause.lower()
    assert "install" in report.recommended_next_action.lower()
    assert "sk-test-secret-value" not in report.stderr_excerpt
    assert "Command:" in report.diagnostic_summary
