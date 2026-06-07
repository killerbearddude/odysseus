"""
Security tests for the local support-bundle command.

The CLI must be read-only and produce the same redacted zip structure as the
service layer without requiring Docker or external services.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_support_bundle_cli_creates_zip(tmp_path: Path):
    # CLI usage should work in minimal local environments without Docker.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("OPENAI_API_KEY=sk-testsecretvalue1234567890\n", encoding="utf-8")
    output = tmp_path / "support.zip"
    script = Path("scripts/odysseus-support-bundle")

    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(output), "--repo-root", str(repo)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert output.exists()
    with zipfile.ZipFile(output) as archive:
        assert "diagnostics.json" in archive.namelist()
        blob = "\n".join(archive.read(name).decode("utf-8", errors="replace") for name in archive.namelist())
    assert "sk-testsecretvalue" not in blob


def test_support_bundle_cli_does_not_modify_repo_contents(tmp_path: Path):
    # The command is a diagnostic export, not a repair or mutation operation.
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = repo / "marker.txt"
    marker.write_text("unchanged", encoding="utf-8")
    before = {path.relative_to(repo).as_posix(): path.read_text(encoding="utf-8") for path in repo.rglob("*") if path.is_file()}
    output = tmp_path / "support.zip"
    script = Path("scripts/odysseus-support-bundle")

    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(output), "--repo-root", str(repo)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    after = {path.relative_to(repo).as_posix(): path.read_text(encoding="utf-8") for path in repo.rglob("*") if path.is_file()}
    assert after == before
