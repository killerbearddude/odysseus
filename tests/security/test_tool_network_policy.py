"""
Security tests for runner network policy hints.

This PR does not implement a network firewall. These tests ensure the local
runner still fails closed for obvious network-looking commands unless a caller
explicitly marks network access as allowed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from services.tool_runner import LocalToolRunner, RunnerRequest, ToolRunnerError


def _workspace(tmp_path: Path) -> Path:
    """Create a temporary runner workspace."""
    workspace = tmp_path / "data" / "workspaces" / "alice"
    workspace.mkdir(parents=True)
    return workspace


def _request(workspace: Path, **overrides: object) -> RunnerRequest:
    """Build a safe default runner request."""
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


def test_runner_rejects_obvious_network_command_when_disallowed(tmp_path: Path):
    # Prevents a staged command from silently turning into a web request when the
    # policy decision did not allow network access.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        LocalToolRunner(repo_root=tmp_path).run(
            _request(workspace, command="curl", args=("https://example.invalid",))
        )


def test_runner_rejects_network_import_hint_when_disallowed(tmp_path: Path):
    # Python snippets with obvious network libraries are denied before execution
    # unless the higher policy layer explicitly approved network access.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        LocalToolRunner(repo_root=tmp_path).run(
            _request(workspace, args=("-c", "import urllib.request; print('x')"))
        )


def test_runner_allows_non_network_local_command_when_network_disallowed(tmp_path: Path):
    # Local work should still run with network_allowed=False when no network hint
    # is present.
    workspace = _workspace(tmp_path)

    response = LocalToolRunner(repo_root=tmp_path).run(_request(workspace))

    assert response.ok is True
    assert response.network_attempts == ()


def test_runner_records_network_hint_when_explicitly_allowed(tmp_path: Path):
    # The runner does not firewall network access in this PR, but it returns
    # detected hints so later audit/policy layers can record the intent.
    workspace = _workspace(tmp_path)

    response = LocalToolRunner(repo_root=tmp_path).run(
        _request(
            workspace,
            args=("-c", "print('https://example.invalid')"),
            network_allowed=True,
        )
    )

    assert response.ok is True
    assert "https://" in response.network_attempts
