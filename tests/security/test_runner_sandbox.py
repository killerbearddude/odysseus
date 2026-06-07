"""
Security tests for local runner sandbox-like controls.

The local runner is not a full container sandbox. These tests lock in the
available defensive controls: process timeout, output bounds, path constraints,
and redacted structured responses.
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
    """Build a safe default request that individual tests can customize."""
    values = {
        "command": sys.executable,
        "args": ("-c", "print('ok')"),
        "working_dir": str(workspace),
        "timeout_seconds": 3,
        "output_limit_bytes": 128,
        "user_id": "alice",
        "decision_id": "decision-1",
    }
    values.update(overrides)
    return RunnerRequest(**values)  # type: ignore[arg-type]


def test_runner_kills_long_running_process(tmp_path: Path):
    # Prevents a generated command from hanging a worker indefinitely.
    workspace = _workspace(tmp_path)

    response = LocalToolRunner(repo_root=tmp_path).run(
        _request(
            workspace,
            args=("-c", "import time; time.sleep(5)"),
            timeout_seconds=0.2,
        )
    )

    assert response.ok is False
    assert response.killed_for_timeout is True
    assert response.duration_ms < 5000


def test_runner_truncates_oversized_stdout_and_stderr(tmp_path: Path):
    # Bounded output prevents tools from flooding audit logs, memory, or review
    # packets with untrusted content.
    workspace = _workspace(tmp_path)

    response = LocalToolRunner(repo_root=tmp_path).run(
        _request(
            workspace,
            args=(
                "-c",
                "import sys; print('A' * 1000); print('B' * 1000, file=sys.stderr)",
            ),
            output_limit_bytes=64,
        )
    )

    assert response.ok is True
    assert len(response.stdout_excerpt) < 120
    assert len(response.stderr_excerpt) < 120
    assert "[truncated]" in response.stdout_excerpt
    assert "[truncated]" in response.stderr_excerpt


def test_runner_rejects_write_path_outside_workspace_or_staging(tmp_path: Path):
    # Declared write paths are checked through canonical path safety before a
    # command is started.
    workspace = _workspace(tmp_path)

    with pytest.raises(ToolRunnerError):
        LocalToolRunner(repo_root=tmp_path).run(
            _request(workspace, write_paths=(str(tmp_path / "outside.txt"),))
        )


def test_runner_records_created_and_modified_workspace_files(tmp_path: Path):
    # Structured responses expose file effects inside the allowed workspace so a
    # later audit/review layer can summarize side effects.
    workspace = _workspace(tmp_path)
    existing = workspace / "existing.txt"
    existing.write_text("before", encoding="utf-8")

    response = LocalToolRunner(repo_root=tmp_path).run(
        _request(
            workspace,
            args=(
                "-c",
                "from pathlib import Path; Path('created.txt').write_text('new'); Path('existing.txt').write_text('after')",
            ),
            write_paths=(str(workspace / "created.txt"), str(existing)),
        )
    )

    assert response.ok is True
    assert "created.txt" in response.files_created
    assert "existing.txt" in response.files_modified


def test_runner_response_redacts_secret_like_output(tmp_path: Path):
    # Tool output should not leak provider keys back into structured responses.
    workspace = _workspace(tmp_path)

    response = LocalToolRunner(repo_root=tmp_path).run(
        _request(
            workspace,
            args=("-c", "print('sk-testsecretvalue1234567890')"),
        )
    )

    assert response.ok is True
    assert "sk-testsecretvalue" not in response.stdout_excerpt
    assert "[REDACTED" in response.stdout_excerpt
