from __future__ import annotations

import subprocess
from io import BytesIO
"""
Backup/restore regression tests for Odysseus data-safety behavior.

These tests prevent backup archives from becoming undocumented, secret-bearing,
or unsafe to restore without a pre-restore snapshot.
"""


import json
import tarfile
from pathlib import Path

import pytest

from services.backup_service import (
    MANIFEST_ARCHIVE_PATH,
    BackupError,
    create_backup,
    restore_backup,
    verify_backup,
)


def _repo(tmp_path: Path) -> Path:
    """Create a minimal fake Odysseus repo with alpha data files."""
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    (repo / "data" / "app.db").write_text("sqlite placeholder")
    (repo / ".app_key").write_text("local-test-key")
    (repo / ".env").write_text("PROVIDER_API_KEY=secret-value")
    return repo


def _manifest_from_archive(archive: Path) -> dict[str, object]:
    """Read the manifest from a test archive."""
    with _open_tar_for_read(archive) as tar:
        member = tar.getmember(MANIFEST_ARCHIVE_PATH)
        extracted = tar.extractfile(member)
        assert extracted is not None
        return json.loads(extracted.read().decode("utf-8"))



def _open_tar_for_read(archive: Path) -> tarfile.TarFile:
    """Open plain tar or zstd-compressed tar archives for test inspection."""
    raw = archive.read_bytes()
    if raw.startswith(b"\x28\xb5\x2f\xfd"):
        proc = subprocess.run(
            ["zstd", "-dc", str(archive)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return tarfile.open(fileobj=BytesIO(proc.stdout), mode="r:*")
    return tarfile.open(archive, "r:*")

def test_create_backup_includes_manifest_and_database(tmp_path: Path):
    # Regression guard: a backup without manifest/database cannot be verified before restore.
    repo = _repo(tmp_path)
    archive = tmp_path / "odysseus-test.tar.zst"

    create_backup(repo, archive)
    verification = verify_backup(archive)

    assert verification.manifest["name"] == "odysseus-backup"
    assert verification.manifest["contains_database"] is True
    with _open_tar_for_read(archive) as tar:
        names = set(tar.getnames())
    assert MANIFEST_ARCHIVE_PATH in names
    assert "odysseus-backup/data/app.db" in names


def test_create_backup_warns_when_app_key_missing(tmp_path: Path):
    # Regression guard: operators must be warned when encrypted/session material may not restore.
    repo = _repo(tmp_path)
    (repo / ".app_key").unlink()
    archive = tmp_path / "missing-key.tar.zst"

    with pytest.warns(UserWarning, match="app_key"):
        create_backup(repo, archive)

    manifest = _manifest_from_archive(archive)
    assert manifest["contains_app_key"] is False


def test_restore_requires_confirmation(tmp_path: Path):
    # Regression guard: restore is destructive and must require explicit confirmation.
    repo = _repo(tmp_path)
    archive = tmp_path / "backup.tar.zst"
    create_backup(repo, archive)

    with pytest.raises(BackupError, match="confirmation"):
        restore_backup(repo, archive)


def test_restore_creates_pre_restore_snapshot(tmp_path: Path):
    # Regression guard: live data must be snapshotted before restore overwrites files.
    repo = _repo(tmp_path)
    archive = tmp_path / "backup.tar.zst"
    create_backup(repo, archive)
    (repo / "data" / "app.db").write_text("modified live db")

    snapshot = restore_backup(repo, archive, yes=True)

    assert snapshot.exists()
    assert snapshot.name.startswith("pre-restore-")
    assert (repo / "data" / "app.db").read_text() == "sqlite placeholder"


def test_backup_output_inside_live_data_is_rejected(tmp_path: Path):
    # Regression guard: recursive self-inclusion can produce unusable backups.
    repo = _repo(tmp_path)

    with pytest.raises(BackupError, match="must not be written under"):
        create_backup(repo, repo / "data" / "bad.tar.zst")
