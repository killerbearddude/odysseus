"""
Security tests for redacted support bundle contents.

These tests prevent regressions where support bundles accidentally include raw
secrets, uploaded files, private documents, or symlink-escaped output paths.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from services.support_bundle import SupportBundleError, create_support_bundle, redact_diagnostics_text


def _read_zip_text(zip_path: Path, name: str) -> str:
    with zipfile.ZipFile(zip_path) as archive:
        return archive.read(name).decode("utf-8")


def test_support_bundle_zip_is_created_with_diagnostics(tmp_path: Path):
    # The bundle should contain a diagnostics snapshot as its primary artifact.
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "odysseus-support.zip"

    created = create_support_bundle(output, repo_root=repo, allowed_output_roots=(tmp_path,))

    assert created == output
    with zipfile.ZipFile(output) as archive:
        assert "diagnostics.json" in archive.namelist()
        diagnostics = json.loads(archive.read("diagnostics.json"))
    assert diagnostics["app"]["name"] == "odysseus"


def test_support_bundle_excludes_raw_env_app_key_uploads_and_documents(tmp_path: Path):
    # Bundles may summarize config presence but must never include private files.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("OPENAI_API_KEY=sk-testsecretvalue1234567890\nPASSWORD=hunter2\n", encoding="utf-8")
    (repo / ".app_key").write_text("super-secret-app-key", encoding="utf-8")
    uploads = repo / "uploads"
    uploads.mkdir()
    (uploads / "private-document.txt").write_text("private upload body", encoding="utf-8")
    data = repo / "data"
    data.mkdir()
    (data / "email-body.txt").write_text("private email contents", encoding="utf-8")

    output = tmp_path / "bundle.zip"
    create_support_bundle(output, repo_root=repo, allowed_output_roots=(tmp_path,))

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        blob = "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in names
            if not name.endswith("/")
        )

    assert ".env" not in names
    assert ".app_key" not in names
    assert all(not name.startswith("uploads/") for name in names)
    assert "sk-testsecretvalue" not in blob
    assert "hunter2" not in blob
    assert "super-secret-app-key" not in blob
    assert "private upload body" not in blob
    assert "private email contents" not in blob
    assert "[REDACTED" in blob


def test_support_bundle_redacts_logs(tmp_path: Path):
    # Redacted logs are useful, but bearer tokens and cookies must not persist.
    repo = tmp_path / "repo"
    repo.mkdir()
    logs = repo / "logs"
    logs.mkdir()
    (logs / "app.log").write_text(
        "Authorization: Bearer abc.def.ghi\nSet-Cookie: session=secret\nPASSWORD=hunter2\n",
        encoding="utf-8",
    )
    output = tmp_path / "bundle.zip"

    create_support_bundle(output, repo_root=repo, allowed_output_roots=(tmp_path,))

    log_text = _read_zip_text(output, "logs/app.log")
    assert "abc.def.ghi" not in log_text
    assert "session=secret" not in log_text
    assert "hunter2" not in log_text
    assert "[REDACTED" in log_text


def test_support_bundle_refuses_symlink_output_escape(tmp_path: Path):
    # The output path itself must not be a symlink to an attacker-chosen target.
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.zip"
    link = tmp_path / "bundle.zip"
    link.symlink_to(outside)

    with pytest.raises(SupportBundleError):
        create_support_bundle(link, repo_root=repo, allowed_output_roots=(tmp_path,))


def test_diagnostic_text_redactor_covers_common_secret_forms():
    # Support-bundle redaction needs broader HTTP/config patterns than audit text.
    text = "\n".join(
        [
            "OPENAI_API_KEY=sk-testsecretvalue1234567890",
            "Authorization: Bearer abc.def.ghi",
            "Set-Cookie: session=secret",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
        ]
    )

    redacted = redact_diagnostics_text(text)

    assert "sk-testsecretvalue" not in redacted
    assert "abc.def.ghi" not in redacted
    assert "session=secret" not in redacted
    assert "OPENSSH PRIVATE KEY" not in redacted
    assert redacted.count("[REDACTED") >= 4
