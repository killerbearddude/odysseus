from __future__ import annotations

import subprocess
from io import BytesIO
# --- Issue 18 backup/restore archive safety regression tests -----------------

import io
import json
import tarfile

from pathlib import Path

import pytest

from services.backup_service import BackupError, create_backup, verify_backup


def _write_issue18_manifest(tar: tarfile.TarFile) -> None:
    """Write a minimal valid manifest for malicious archive structure tests."""
    encoded = json.dumps({"name": "odysseus-backup"}).encode("utf-8")
    info = tarfile.TarInfo("odysseus-backup/BACKUP_MANIFEST.json")
    info.size = len(encoded)
    tar.addfile(info, io.BytesIO(encoded))


def _issue18_malicious_archive(tmp_path: Path, member: tarfile.TarInfo) -> Path:
    """Create a test archive with one malicious member."""
    archive = tmp_path / "malicious.tar.zst"
    with tarfile.open(archive, "w") as tar:
        _write_issue18_manifest(tar)
        if member.isfile() and member.size == 0:
            member.size = 1
            tar.addfile(member, io.BytesIO(b"x"))
        else:
            tar.addfile(member)
    return archive



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

def test_issue18_verify_rejects_absolute_path_archive_entry(tmp_path: Path):
    # Regression guard: restore must reject absolute archive paths before writing files.
    member = tarfile.TarInfo("/tmp/escape.txt")
    member.size = 1
    archive = _issue18_malicious_archive(tmp_path, member)

    with pytest.raises(BackupError, match="absolute path"):
        verify_backup(archive)


def test_issue18_verify_rejects_traversal_archive_entry(tmp_path: Path):
    # Regression guard: ../ traversal must not escape the restore root.
    member = tarfile.TarInfo("odysseus-backup/../../escape.txt")
    member.size = 1
    archive = _issue18_malicious_archive(tmp_path, member)

    with pytest.raises(BackupError, match="traversal"):
        verify_backup(archive)


def test_issue18_verify_rejects_symlink_archive_entry(tmp_path: Path):
    # Regression guard: symlink entries can redirect restore writes outside the repo.
    member = tarfile.TarInfo("odysseus-backup/data/app.db")
    member.type = tarfile.SYMTYPE
    member.linkname = "../../outside"
    archive = _issue18_malicious_archive(tmp_path, member)

    with pytest.raises(BackupError, match="unsafe member type"):
        verify_backup(archive)


def test_issue18_verify_rejects_special_file_archive_entry(tmp_path: Path):
    # Regression guard: backups must not recreate device/FIFO-like special files.
    member = tarfile.TarInfo("odysseus-backup/data/fifo")
    member.type = tarfile.FIFOTYPE
    archive = _issue18_malicious_archive(tmp_path, member)

    with pytest.raises(BackupError, match="unsafe member type|special file"):
        verify_backup(archive)


def test_issue18_backup_excludes_caches_logs_and_virtualenv(tmp_path: Path):
    # Regression guard: backup archives must not accidentally include runtime/cache bloat.
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    (repo / "data" / "app.db").write_text("db")
    (repo / ".app_key").write_text("key")
    (repo / ".venv").mkdir()
    (repo / ".venv" / "secret.txt").write_text("do not include")
    (repo / "logs").mkdir()
    (repo / "logs" / "app.log").write_text("runtime log")
    (repo / "data" / "__pycache__").mkdir()
    (repo / "data" / "__pycache__" / "x.pyc").write_bytes(b"bytecode")
    archive = tmp_path / "backup.tar.zst"

    create_backup(repo, archive)

    with _open_tar_for_read(archive) as tar:
        names = "\n".join(tar.getnames())
    assert ".venv" not in names
    assert "__pycache__" not in names
    assert "logs/app.log" not in names


def test_issue18_manifest_does_not_store_raw_provider_tokens(tmp_path: Path):
    # Regression guard: manifests may report .env presence but never raw secrets.
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    (repo / "data" / "app.db").write_text("db")
    (repo / ".app_key").write_text("key")
    (repo / ".env").write_text("OPENAI_API_KEY=sk-test-secret-value")
    archive = tmp_path / "backup.tar.zst"

    create_backup(repo, archive)

    with _open_tar_for_read(archive) as tar:
        env_name = next(name for name in tar.getnames() if name.endswith(".env"))
        env_member = tar.extractfile(env_name)
        assert env_member is not None
        assert b"sk-test-secret-value" in env_member.read()
    with _open_tar_for_read(archive) as tar:
        manifest_file = tar.extractfile("odysseus-backup/BACKUP_MANIFEST.json")
        assert manifest_file is not None
        manifest_text = manifest_file.read().decode("utf-8")
    assert "sk-test-secret-value" not in manifest_text
    assert '"contains_env": true' in manifest_text
