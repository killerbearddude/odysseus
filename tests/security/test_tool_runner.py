"""
Security tests for the local tool runner interface.

These tests prove the runner fails closed for unsafe request shape before any
future shell/Python/background-job integration wires real tools through it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from services.tool_runner import LocalToolRunner, RunnerRequest, ToolRunnerError


def _workspace(tmp_path: Path) -> Path:
    """Create a temporary Odysseus workspace root for runner tests."""
    workspace = tmp_path / "data" / "workspaces" / "alice"
    workspace.mkdir(parents=True)
    return workspace


def _runner(tmp_path: Path) -> LocalToolRunner:
    """Return a runner bound to a temporary repository root."""
    return LocalToolRunner(repo_root=tmp_path)


def _request(workspace: Path, **overrides: object) -> RunnerRequest:
    """Build a minimal safe Python runner request for tests."""
    values = {
        "command": sys.executable,
        "args": ("-c", "print('ok')"),
        "working_dir": str(workspace),
        "timeout_seconds": 3,
        "output_limit_bytes": 4096,
        "user_id": "alice",
        "decision_id": "decision-1",
    }
    values.update(overrides)
    return RunnerRequest(**values)  # type: ignore[arg-type]


def test_runner_rejects_cwd_outside_workspace_or_staging(tmp_path: Path):
    # Prevents a tool call from using project root, /tmp, /etc, or another broad
    # host path as the execution directory.
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ToolRunnerError):
        _runner(tmp_path).run(_request(outside))


def test_runner_rejects_missing_timeout(tmp_path: Path):
    # Timeouts are mandatory so future integrations cannot accidentally create
    # long-lived or hung subprocesses.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        _runner(tmp_path).run(_request(workspace, timeout_seconds=None))


def test_runner_does_not_inherit_provider_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # The child process should not inherit OPENAI_API_KEY or similar local env
    # values from the Odysseus server process.
    workspace = _workspace(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-testsecretvalue1234567890")

    response = _runner(tmp_path).run(
        _request(
            workspace,
            args=("-c", "import os; print(os.getenv('OPENAI_API_KEY', 'missing'))"),
        )
    )

    assert response.ok is True
    assert "missing" in response.stdout_excerpt
    assert "sk-testsecretvalue" not in response.stdout_excerpt


def test_runner_allows_explicit_safe_environment(tmp_path: Path):
    # Explicit environment values must be allowlisted so callers cannot smuggle
    # credentials into a subprocess under arbitrary variable names.
    workspace = _workspace(tmp_path)

    response = _runner(tmp_path).run(
        _request(
            workspace,
            environment={"ODYSSEUS_RUNNER_SAFE_FLAG": "enabled"},
            args=("-c", "import os; print(os.getenv('ODYSSEUS_RUNNER_SAFE_FLAG'))"),
        )
    )

    assert response.ok is True
    assert "enabled" in response.stdout_excerpt


def test_runner_rejects_secret_environment_values(tmp_path: Path):
    # Even allowlisted keys cannot carry token-shaped values.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        _runner(tmp_path).run(
            _request(
                workspace,
                environment={"ODYSSEUS_RUNNER_SAFE_FLAG": "sk-testsecretvalue1234567890"},
            )
        )


def test_runner_rejects_shell_unless_reviewed(tmp_path: Path):
    # shell=True should be impossible unless a reviewed staging flow explicitly
    # marks the request as a reviewed shell action.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        _runner(tmp_path).run(_request(workspace, command="echo ok", args=(), shell=True))
