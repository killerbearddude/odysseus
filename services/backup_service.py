"""
Read-only backup, verification, and restore helpers for Odysseus alpha data.

The service keeps backup behavior explicit and testable. It writes a redacted
manifest, rejects unsafe archive entries before restore, and creates a
pre-restore snapshot before overwriting live files. It intentionally does not
implement cloud backups, encryption UI, or scheduled backup automation.
"""

from __future__ import annotations

import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator


ARCHIVE_ROOT = "odysseus-backup"
MANIFEST_NAME = "BACKUP_MANIFEST.json"
MANIFEST_ARCHIVE_PATH = f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"

DEFAULT_INCLUDE_PATHS = (
    "data",
    "uploads",
    "generated",
    "documents",
    ".app_key",
    ".env",
)

EXCLUDED_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "backups",
    "logs",
    "node_modules",
}

EXCLUDED_SUFFIXES = (
    ".pyc",
    ".pyo",
)

DANGEROUS_RESTORE_TYPES = {
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
    tarfile.CHRTYPE,
    tarfile.BLKTYPE,
    tarfile.FIFOTYPE,
}


class BackupError(RuntimeError):
    """Raised when backup, verification, or restore safety checks fail."""


@dataclass(frozen=True)
class BackupVerification:
    """
    Result returned by successful archive verification.

    Attributes:
        manifest: Parsed redacted backup manifest.
        member_count: Number of archive members inspected.
    """

    manifest: dict[str, object]
    member_count: int


def _utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 form."""
    return datetime.now(timezone.utc).isoformat()


def _git_commit(repo_root: Path) -> str:
    """Return the current short Git commit, or ``unknown`` outside Git."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _schema_version(repo_root: Path) -> str:
    """Return a best-effort schema version marker without opening raw content."""
    db_path = repo_root / "data" / "app.db"
    if db_path.exists():
        return "sqlite-present"
    return "unknown"


def _is_relative_to(path: Path, root: Path) -> bool:
    """Compatibility wrapper for path containment checks."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_output_path(repo_root: Path, output_path: Path) -> Path:
    """
    Validate where a backup archive may be written.

    The backup command may write to ``./backups`` or another operator-selected
    location, but it refuses output under live source directories such as
    ``data`` or ``uploads``. That prevents recursive self-inclusion and avoids
    burying backup archives inside user data.
    """
    output = output_path.expanduser()
    if output.is_symlink():
        raise BackupError("backup output path must not be a symlink")

    output_parent = output.parent.resolve(strict=False)
    output_parent.mkdir(parents=True, exist_ok=True)
    resolved_output = output_parent / output.name

    forbidden_roots = [
        repo_root / "data",
        repo_root / "uploads",
        repo_root / "generated",
        repo_root / "documents",
        repo_root / "logs",
    ]
    for forbidden in forbidden_roots:
        resolved_forbidden = forbidden.resolve(strict=False)
        if _is_relative_to(resolved_output.resolve(strict=False), resolved_forbidden):
            raise BackupError(f"backup output must not be written under {forbidden}")

    return resolved_output


def _should_exclude(path: Path, repo_root: Path) -> bool:
    """Return whether a repository path should be excluded from backups."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True

    parts = set(rel.parts)
    if parts & EXCLUDED_DIR_NAMES:
        return True
    if path.name in EXCLUDED_DIR_NAMES:
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    return False


def _iter_backup_files(repo_root: Path, include_paths: Iterable[str]) -> Iterator[Path]:
    """
    Yield regular files selected for backup without following symlinks.

    Symlinks are intentionally skipped. Restoring links from archives is also
    rejected, so backup creation should not produce links either.
    """
    for relative in include_paths:
        source = repo_root / relative
        if not source.exists() and not source.is_symlink():
            continue
        if source.is_symlink():
            continue
        if source.is_file():
            if not _should_exclude(source, repo_root):
                yield source
            continue
        if source.is_dir():
            for current_root, dirs, files in os.walk(source, followlinks=False):
                root_path = Path(current_root)
                dirs[:] = [d for d in dirs if not _should_exclude(root_path / d, repo_root)]
                for filename in files:
                    candidate = root_path / filename
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    if not _should_exclude(candidate, repo_root):
                        yield candidate


def _tar_reader(archive_path: Path):
    """
    Open a backup archive for reading.

    Archives created without the optional ``zstd`` binary are plain tar files,
    even if operators choose a ``.tar.zst`` filename. Archives created with the
    ``zstd`` binary are transparently decompressed for verification/restore.
    """
    with archive_path.open("rb") as handle:
        magic = handle.read(4)

    if magic == b"\x28\xb5\x2f\xfd":
        if shutil.which("zstd") is None:
            raise BackupError("zstd-compressed backup requires the zstd command")
        process = subprocess.Popen(["zstd", "-q", "-dc", str(archive_path)], stdout=subprocess.PIPE)
        if process.stdout is None:
            raise BackupError("failed to open zstd decompressor")
        return tarfile.open(fileobj=process.stdout, mode="r|*"), process

    return tarfile.open(archive_path, mode="r:*"), None


def _write_manifest(tar: tarfile.TarFile, manifest: dict[str, object]) -> None:
    """Write ``BACKUP_MANIFEST.json`` into the archive without raw secrets."""
    encoded = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    info = tarfile.TarInfo(MANIFEST_ARCHIVE_PATH)
    info.size = len(encoded)
    info.mtime = int(datetime.now(timezone.utc).timestamp())
    info.mode = 0o600
    tar.addfile(info, io.BytesIO(encoded))


def _build_manifest(repo_root: Path, included_paths: list[str], excluded_paths: list[str]) -> dict[str, object]:
    """Build the redacted backup manifest stored in every archive."""
    return {
        "name": "odysseus-backup",
        "created_at": _utc_now(),
        "app_commit": _git_commit(repo_root),
        "schema_version": _schema_version(repo_root),
        "included_paths": included_paths,
        "excluded_paths": excluded_paths,
        "host_platform": platform.platform(),
        "python_version": platform.python_version(),
        "archive_format": "tar.zst",
        "contains_app_key": (repo_root / ".app_key").exists(),
        "contains_env": (repo_root / ".env").exists(),
        "contains_database": (repo_root / "data" / "app.db").exists(),
    }


def create_backup(repo_root: Path, output_path: Path, *, include_paths: Iterable[str] = DEFAULT_INCLUDE_PATHS) -> Path:
    """
    Create an Odysseus backup archive and return its path.

    The manifest records presence/absence of sensitive files but never stores
    raw secret values. Missing ``.app_key`` emits a warning because restoring a
    database without its matching app key can break encrypted/session material.
    """
    repo_root = repo_root.resolve(strict=False)
    output = _validate_output_path(repo_root, output_path)

    if not (repo_root / ".app_key").exists():
        warnings.warn(
            ".app_key is missing from the backup source; restore may be incomplete",
            UserWarning,
            stacklevel=2,
        )

    files = sorted(set(_iter_backup_files(repo_root, include_paths)))
    included = [str(path.relative_to(repo_root)) for path in files]
    excluded = sorted(EXCLUDED_DIR_NAMES | {"*.pyc", "*.pyo"})
    manifest = _build_manifest(repo_root, included, excluded)

    with tempfile.TemporaryDirectory(prefix="odysseus-backup-") as tmp:
        tmp_tar = Path(tmp) / "backup.tar"
        with tarfile.open(tmp_tar, mode="w", format=tarfile.PAX_FORMAT) as tar:
            _write_manifest(tar, manifest)
            for source in files:
                archive_name = f"{ARCHIVE_ROOT}/{source.relative_to(repo_root).as_posix()}"
                tar.add(source, arcname=archive_name, recursive=False)

        if output.suffix == ".zst" and shutil.which("zstd") is not None:
            subprocess.run(["zstd", "-q", "-f", str(tmp_tar), "-o", str(output)], check=True)
        else:
            shutil.copyfile(tmp_tar, output)

    return output


def _validate_member_name(name: str) -> PurePosixPath:
    """Validate one archive member name before restore."""
    pure = PurePosixPath(name)
    if pure.is_absolute():
        raise BackupError(f"backup archive contains absolute path: {name}")
    if ".." in pure.parts:
        raise BackupError(f"backup archive contains traversal path: {name}")
    if not pure.parts or pure.parts[0] != ARCHIVE_ROOT:
        raise BackupError(f"backup archive has unexpected top-level path: {name}")
    return pure


def _validate_member_type(member: tarfile.TarInfo) -> None:
    """Reject archive member types that can escape or mutate system state."""
    if member.type in DANGEROUS_RESTORE_TYPES:
        raise BackupError(f"backup archive contains unsafe member type: {member.name}")
    if member.isdev() or member.isfifo():
        raise BackupError(f"backup archive contains special file: {member.name}")


def verify_backup(archive_path: Path) -> BackupVerification:
    """
    Verify archive structure and return the parsed manifest.

    Verification is deliberately performed before restore writes any file. The
    function rejects absolute paths, traversal, symlinks, hardlinks, device
    files, FIFOs, and unexpected top-level layouts.
    """
    archive_path = archive_path.expanduser()
    if not archive_path.exists():
        raise BackupError(f"backup archive does not exist: {archive_path}")

    tar, process = _tar_reader(archive_path)
    manifest: dict[str, object] | None = None
    member_count = 0
    try:
        with tar:
            for member in tar:
                member_count += 1
                _validate_member_name(member.name)
                _validate_member_type(member)
                if member.name == MANIFEST_ARCHIVE_PATH:
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        raise BackupError("backup manifest could not be read")
                    manifest = json.loads(extracted.read().decode("utf-8"))
    finally:
        if process is not None:
            if process.stdout:
                process.stdout.close()
            rc = process.wait(timeout=10)
            if rc != 0:
                raise BackupError("zstd decompression failed during verification")

    if manifest is None:
        raise BackupError("backup archive is missing BACKUP_MANIFEST.json")
    if manifest.get("name") != "odysseus-backup":
        raise BackupError("backup manifest is not an Odysseus backup manifest")

    return BackupVerification(manifest=manifest, member_count=member_count)


def _safe_destination(repo_root: Path, member_name: str) -> Path:
    """Return the restore destination for a verified archive member."""
    pure = _validate_member_name(member_name)
    relative = PurePosixPath(*pure.parts[1:])
    destination = repo_root / Path(relative.as_posix())
    resolved = destination.resolve(strict=False)
    if not _is_relative_to(resolved, repo_root):
        raise BackupError(f"restore destination escapes repository: {member_name}")
    return destination


def restore_backup(repo_root: Path, archive_path: Path, *, yes: bool = False) -> Path:
    """
    Restore a verified backup archive into ``repo_root``.

    A pre-restore snapshot is created before any archive member is written. The
    caller must pass ``yes=True`` after human confirmation; the CLI maps this to
    the ``--yes`` flag.
    """
    if not yes:
        raise BackupError("restore requires explicit confirmation; pass --yes")

    repo_root = repo_root.resolve(strict=False)
    verification = verify_backup(archive_path)
    if not verification.manifest.get("contains_app_key"):
        warnings.warn(
            "backup manifest says .app_key is missing; restored data may not be usable",
            UserWarning,
            stacklevel=2,
        )

    snapshot_dir = repo_root / "backups"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = snapshot_dir / f"pre-restore-{stamp}.tar.zst"
    create_backup(repo_root, snapshot)

    tar, process = _tar_reader(archive_path)
    try:
        with tar:
            for member in tar:
                _validate_member_name(member.name)
                _validate_member_type(member)
                if member.name == MANIFEST_ARCHIVE_PATH:
                    continue
                destination = _safe_destination(repo_root, member.name)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                source = tar.extractfile(member)
                if source is None:
                    raise BackupError(f"failed to read archive member: {member.name}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                destination.chmod(member.mode & 0o777)
    finally:
        if process is not None:
            if process.stdout:
                process.stdout.close()
            rc = process.wait(timeout=10)
            if rc != 0:
                raise BackupError("zstd decompression failed during restore")

    return snapshot
