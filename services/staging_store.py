"""
Filesystem-backed staging store for Odysseus generated artifacts.

This module persists generated scripts, file patches, command reviews, email
Drafts, model configuration changes, and rejected artifacts under a single
staging root. It does not execute anything; it only writes reviewable drafts so
higher-risk actions can follow the safer generate -> stage -> review -> approve
workflow.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final


# All artifact categories are application-owned. Callers choose a known category
# but never provide arbitrary output paths, which avoids path traversal and
# symlink-based writes outside the staging tree.
ARTIFACT_SUBDIRS: Final[dict[str, str]] = {
    "generated-script": "generated-scripts",
    "file-patch": "file-patches",
    "command-review": "command-reviews",
    "email-draft": "email-drafts",
    "model-config-change": "model-config-changes",
}
REJECTED_SUBDIR: Final[str] = "rejected"
DEFAULT_STAGING_ROOT: Final[Path] = Path("data/staging")


class StagingStoreError(ValueError):
    """Raised when staged artifact persistence would violate staging policy."""


@dataclass(frozen=True)
class StagedArtifact:
    """
    Metadata returned after writing or moving a staged artifact.

    Attributes:
        artifact_id: Server-generated artifact identifier.
        artifact_type: Static artifact category such as ``generated-script``.
        path: Absolute path to the staged file.
        relative_path: Path relative to the staging root for display/review.
        content_hash: SHA-256 hash of the staged bytes.
        size_bytes: Number of bytes written to disk.
        created_at: UTC timestamp for artifact creation or rejection movement.
        rejected: True when the artifact now lives under the rejected area.
    """

    artifact_id: str
    artifact_type: str
    path: Path
    relative_path: Path
    content_hash: str
    size_bytes: int
    created_at: datetime
    rejected: bool = False


AuditHook = Callable[[str, dict[str, object]], None]


def _hash_bytes(content: bytes) -> str:
    """
    Return a SHA-256 digest for staged content.

    Args:
        content: Raw bytes to hash.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    import hashlib

    return hashlib.sha256(content).hexdigest()


def _safe_extension(extension: str) -> str:
    """
    Normalize a file extension for server-generated artifact names.

    Args:
        extension: Requested extension such as ``.sh`` or ``md``.

    Returns:
        A safe extension beginning with ``.``.

    Raises:
        StagingStoreError: If the extension contains path separators or traversal.
    """
    candidate = extension.strip() or ".txt"
    if not candidate.startswith("."):
        candidate = f".{candidate}"
    if any(part in candidate for part in ("/", "\\", "..")):
        raise StagingStoreError("artifact extension must be a simple file suffix")
    return candidate


def _now_utc() -> datetime:
    """Return a timezone-aware UTC timestamp for artifact metadata."""
    return datetime.now(timezone.utc)


class StagingStore:
    """
    Persist reviewable generated artifacts under ``data/staging``.

    The store owns path construction and artifact identifiers. Callers cannot
    supply absolute output paths or filenames because staged artifacts are part
    of the trust boundary for generated actions.
    """

    def __init__(self, root: str | Path = DEFAULT_STAGING_ROOT, *, audit_hook: AuditHook | None = None) -> None:
        """
        Initialize a staging store.

        Args:
            root: Staging root. Tests may pass a temporary root.
            audit_hook: Optional callback receiving lightweight staging events.

        Side effects:
            Creates the staging root and expected category directories.
        """
        root_path = Path(root).expanduser()
        self.audit_hook = audit_hook
        # Validate the caller-supplied root before resolving it. A symlinked
        # staging root would make later child-path checks depend on attacker-
        # controlled filesystem state.
        self._ensure_directory(root_path)
        self.root = root_path.resolve(strict=True)
        self._ensure_under_root(self.root)
        for subdir in (*ARTIFACT_SUBDIRS.values(), REJECTED_SUBDIR):
            category_dir = self.root / subdir
            self._ensure_directory(category_dir)
            self._ensure_under_root(category_dir)

    def stage_artifact(
        self,
        artifact_type: str,
        content: str | bytes,
        *,
        extension: str = ".txt",
    ) -> StagedArtifact:
        """
        Persist a new staged artifact atomically.

        Args:
            artifact_type: One of the static artifact categories.
            content: Text or bytes to persist as a draft artifact.
            extension: Safe file suffix for the generated filename.

        Returns:
            Metadata describing the staged artifact.

        Raises:
            StagingStoreError: If the artifact type or path policy is invalid.
        """
        artifact_id = self.generate_artifact_id()
        content_bytes = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        category_dir = self._category_dir(artifact_type)
        artifact_path = self._artifact_path(category_dir, artifact_id, _safe_extension(extension))

        if artifact_path.exists():
            # UUID collisions are extremely unlikely, but overwriting generated
            # artifacts would undermine review integrity, so fail closed.
            raise StagingStoreError("staged artifact already exists")

        self._write_atomic(artifact_path, content_bytes)
        artifact = self._artifact_metadata(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=artifact_path,
            content_bytes=content_bytes,
            rejected=False,
        )
        self._emit("tool_staged", {"artifact_id": artifact.artifact_id, "artifact_type": artifact.artifact_type})
        return artifact

    def reject_artifact(self, artifact_type: str, artifact_id: str) -> StagedArtifact:
        """
        Move an artifact into the rejected staging area.

        Args:
            artifact_type: Artifact category where the draft currently lives.
            artifact_id: Server-generated artifact identifier.

        Returns:
            Metadata for the rejected artifact location.

        Raises:
            StagingStoreError: If the artifact cannot be found or safely moved.
        """
        source = self.find_artifact_path(artifact_type, artifact_id)
        if source is None:
            raise StagingStoreError("staged artifact not found")

        rejected_dir = self.root / REJECTED_SUBDIR
        self._ensure_under_root(rejected_dir)
        destination = rejected_dir / f"{artifact_id}-{artifact_type}{source.suffix}"
        self._ensure_under_root(destination)
        if destination.exists():
            raise StagingStoreError("rejected artifact already exists")

        content_bytes = source.read_bytes()
        os.replace(source, destination)
        artifact = self._artifact_metadata(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=destination,
            content_bytes=content_bytes,
            rejected=True,
        )
        self._emit("tool_staged", {"artifact_id": artifact.artifact_id, "artifact_type": artifact.artifact_type, "rejected": True})
        return artifact

    def find_artifact_path(self, artifact_type: str, artifact_id: str) -> Path | None:
        """
        Locate a staged artifact by type and server-generated ID.

        Args:
            artifact_type: Static artifact category.
            artifact_id: Server-generated artifact identifier.

        Returns:
            The artifact path, or ``None`` if no matching artifact exists.
        """
        self._validate_artifact_id(artifact_id)
        category_dir = self._category_dir(artifact_type)
        matches = sorted(category_dir.glob(f"{artifact_id}.*"))
        if not matches:
            return None
        if len(matches) > 1:
            raise StagingStoreError("multiple artifacts found for one artifact ID")
        self._ensure_under_root(matches[0])
        return matches[0]

    def generated_script_dir(self) -> Path:
        """
        Return the generated-script staging directory.

        Returns:
            Absolute path to ``generated-scripts`` under the staging root.
        """
        return self._category_dir("generated-script")

    @staticmethod
    def generate_artifact_id() -> str:
        """
        Generate a server-owned artifact ID.

        Returns:
            A 32-character UUID4 hex string.
        """
        return uuid.uuid4().hex

    def _category_dir(self, artifact_type: str) -> Path:
        """
        Resolve an artifact category directory under the staging root.

        Args:
            artifact_type: Static artifact category.

        Returns:
            Absolute category directory.
        """
        subdir = ARTIFACT_SUBDIRS.get(artifact_type)
        if subdir is None:
            raise StagingStoreError(f"unknown staged artifact type: {artifact_type}")
        category_dir = self.root / subdir
        self._ensure_under_root(category_dir)
        return category_dir

    def _artifact_path(self, category_dir: Path, artifact_id: str, extension: str) -> Path:
        """
        Build a safe artifact path from server-owned components.

        Args:
            category_dir: Already validated artifact category directory.
            artifact_id: Server-generated artifact ID.
            extension: Safe file suffix.

        Returns:
            Absolute path for the staged artifact.
        """
        self._validate_artifact_id(artifact_id)
        artifact_path = category_dir / f"{artifact_id}{extension}"
        self._ensure_under_root(artifact_path)
        return artifact_path

    def _write_atomic(self, destination: Path, content: bytes) -> None:
        """
        Atomically write bytes to a destination within staging.

        Args:
            destination: Final path under the staging root.
            content: Bytes to write.
        """
        self._ensure_under_root(destination)
        self._reject_symlink(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, destination)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _artifact_metadata(
        self,
        *,
        artifact_id: str,
        artifact_type: str,
        path: Path,
        content_bytes: bytes,
        rejected: bool,
    ) -> StagedArtifact:
        """
        Build metadata for a staged artifact.

        Args:
            artifact_id: Server-generated artifact ID.
            artifact_type: Static artifact category.
            path: Artifact location.
            content_bytes: Persisted artifact bytes.
            rejected: Whether the artifact lives under rejected storage.

        Returns:
            Staged artifact metadata.
        """
        self._ensure_under_root(path)
        return StagedArtifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=path,
            relative_path=path.resolve(strict=False).relative_to(self.root),
            content_hash=_hash_bytes(content_bytes),
            size_bytes=len(content_bytes),
            created_at=_now_utc(),
            rejected=rejected,
        )

    def _ensure_directory(self, path: Path) -> None:
        """
        Ensure a directory exists and does not escape the staging root by symlink.

        Args:
            path: Directory to create or validate.
        """
        if path.exists() and path.is_symlink():
            raise StagingStoreError("staging directory must not be a symlink")
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            raise StagingStoreError("staging path is not a directory")

    def _ensure_under_root(self, path: Path) -> None:
        """
        Validate that a path resolves under the staging root.

        Args:
            path: Candidate path.

        Raises:
            StagingStoreError: If the path escapes the staging root.
        """
        resolved = path.expanduser().resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise StagingStoreError("staged artifact path escapes staging root") from exc

    @staticmethod
    def _reject_symlink(path: Path) -> None:
        """
        Reject writes through symlinked final paths.

        Args:
            path: Candidate final artifact path.
        """
        if path.exists() and path.is_symlink():
            raise StagingStoreError("staged artifact path must not be a symlink")

    @staticmethod
    def _validate_artifact_id(artifact_id: str) -> None:
        """
        Validate server-generated artifact ID format.

        Args:
            artifact_id: Artifact ID to validate.
        """
        if len(artifact_id) != 32 or not all(ch in "0123456789abcdef" for ch in artifact_id):
            raise StagingStoreError("invalid staged artifact ID")

    def _emit(self, event_type: str, metadata: dict[str, object]) -> None:
        """
        Emit an optional audit hook without coupling this module to audit storage.

        Args:
            event_type: Lightweight event name.
            metadata: Event metadata safe for tests or later audit integration.
        """
        if self.audit_hook is not None:
            self.audit_hook(event_type, metadata)
