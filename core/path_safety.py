"""
Central canonical path-safety helpers for Odysseus.

This module owns filesystem path normalization and allowlist checks for tools,
imports, generated files, and future sandbox/staging enforcement. It is kept
separate from route and tool execution code so model-generated arguments cannot
choose their own filesystem trust boundary.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable


class PathSafetyError(ValueError):
    """Raised when a user/tool path violates Odysseus filesystem policy."""


# Repository-relative storage roots that Odysseus controls. Future deployment
# modes may remap these through configuration, but the default policy keeps all
# file-tool access inside explicit application-owned directories.
DEFAULT_APPROVED_ROOTS: tuple[str, ...] = (
    "data/workspaces",
    "data/uploads",
    "data/imports",
    "data/staging",
    "data/generated",
    "data/backups",
)

# Writes are intentionally narrower than reads: backup reads may be valid, but
# new file writes should land in workspaces, staging, generated output, uploads,
# or import quarantine paths until a later review/audit flow owns them.
DEFAULT_WRITE_ROOTS: tuple[str, ...] = (
    "data/workspaces",
    "data/uploads",
    "data/imports",
    "data/staging",
    "data/generated",
)

# Import sources must already be inside Odysseus-controlled intake paths. This
# PR validates only the source; a later PR should copy imports into controlled
# storage and attach provenance metadata.
DEFAULT_IMPORT_ROOTS: tuple[str, ...] = (
    "data/imports",
    "data/uploads",
)

DEFAULT_WORKSPACE_ROOTS: tuple[str, ...] = (
    "data/workspaces",
    "data/staging",
    "data/generated",
)

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Sensitive leaf names and directories are denied even if a caller accidentally
# places them under an approved root. This prevents policy bypasses where a tool
# is pointed at copied secrets or dotfile-like credential stores.
_SENSITIVE_EXACT_COMPONENTS = {
    ".env",
    ".app_key",
    ".ssh",
    ".gnupg",
    ".docker",
    ".kube",
}

_SENSITIVE_COMPONENT_HINTS = (
    "browser",
    "chrome",
    "chromium",
    "firefox",
    "mozilla",
    "brave",
    "cookie",
    "cookies",
    "token",
    "tokens",
    "password-store",
    "password_store",
    "passwords",
    "keyring",
)

# These roots are too broad to be used as allowlist boundaries. A future hardened
# deployment profile may expose narrower absolute roots, but never these broad
# host-level locations as a generic file-tool root.
_FORBIDDEN_ROOTS = {
    Path("/").resolve(),
    Path("/home").resolve(),
    Path("/etc").resolve(),
}

_FORBIDDEN_HOME_CHILDREN = {
    ".ssh",
    ".gnupg",
    ".config",
    ".docker",
    ".kube",
}


PathLike = str | os.PathLike[str]


def canonicalize_path(path: PathLike, *, base_dir: PathLike | None = None) -> Path:
    """
    Normalize a user/tool path into an absolute canonical ``Path``.

    Args:
        path: User, route, or tool supplied path to normalize.
        base_dir: Optional base directory for relative paths. When omitted, the
            repository root is used so default data roots resolve predictably.

    Returns:
        Canonical absolute path with symlinks resolved where possible.

    Raises:
        PathSafetyError: If the path is empty or contains sensitive components.
    """
    raw_path = Path(path).expanduser()
    if str(raw_path).strip() == "":
        raise PathSafetyError("path is empty")

    base = Path(base_dir).expanduser() if base_dir is not None else _REPO_ROOT
    candidate = raw_path if raw_path.is_absolute() else base / raw_path

    # strict=False keeps validation usable for planned write targets that do not
    # exist yet while still resolving existing symlinks in parent directories.
    resolved = candidate.resolve(strict=False)
    _reject_sensitive_components(resolved)
    return resolved


def resolve_allowed_path(
    path: PathLike,
    *,
    approved_roots: Iterable[PathLike] | None = None,
    base_dir: PathLike | None = None,
    must_exist: bool = False,
) -> Path:
    """
    Resolve a path and ensure its final canonical location is under an allowed root.

    Args:
        path: Path supplied by a user, route, or tool call.
        approved_roots: Explicit allowed roots. Defaults to Odysseus-controlled
            data roots when omitted.
        base_dir: Base directory for relative paths and relative root entries.
        must_exist: Require the target to exist after canonicalization.

    Returns:
        Canonical path inside one of the approved roots.

    Raises:
        PathSafetyError: If the path escapes allowed roots or violates sensitive
            path policy.
    """
    base = Path(base_dir).expanduser() if base_dir is not None else _REPO_ROOT
    canonical = canonicalize_path(path, base_dir=base)

    if must_exist and not canonical.exists():
        raise PathSafetyError("path does not exist")

    roots = _canonical_roots(approved_roots or DEFAULT_APPROVED_ROOTS, base_dir=base)
    if not any(_is_relative_to(canonical, root) for root in roots):
        raise PathSafetyError("path is outside approved roots")

    _reject_special_file(canonical)
    return canonical


def validate_read_path(
    path: PathLike,
    *,
    approved_roots: Iterable[PathLike] | None = None,
    base_dir: PathLike | None = None,
) -> Path:
    """
    Validate a path for read-style tool access.

    Args:
        path: Requested read path.
        approved_roots: Optional read allowlist roots.
        base_dir: Optional base directory for relative values.

    Returns:
        Canonical readable path under an approved root.

    Raises:
        PathSafetyError: If the path is outside policy or resolves to an unsafe
            filesystem object.
    """
    return resolve_allowed_path(
        path,
        approved_roots=approved_roots or DEFAULT_APPROVED_ROOTS,
        base_dir=base_dir,
        must_exist=True,
    )


def validate_write_path(
    path: PathLike,
    *,
    approved_roots: Iterable[PathLike] | None = None,
    base_dir: PathLike | None = None,
) -> Path:
    """
    Validate a path for file creation or update.

    Args:
        path: Requested write target. The target may not exist yet.
        approved_roots: Optional write allowlist roots.
        base_dir: Optional base directory for relative values.

    Returns:
        Canonical write target under an approved write root.

    Raises:
        PathSafetyError: If the target or nearest existing parent escapes policy
            or resolves to an unsafe filesystem object.
    """
    canonical = resolve_allowed_path(
        path,
        approved_roots=approved_roots or DEFAULT_WRITE_ROOTS,
        base_dir=base_dir,
        must_exist=False,
    )

    # For new files, validate the nearest existing parent so symlinked parent
    # directories cannot redirect writes outside approved storage.
    existing_parent = canonical if canonical.exists() else _nearest_existing_parent(canonical)
    _reject_special_file(existing_parent)
    return canonical


def validate_import_source(
    path: PathLike,
    *,
    approved_roots: Iterable[PathLike] | None = None,
    base_dir: PathLike | None = None,
) -> Path:
    """
    Validate an import source before ingestion.

    Args:
        path: Candidate source file for import/document ingestion.
        approved_roots: Optional import allowlist roots.
        base_dir: Optional base directory for relative values.

    Returns:
        Canonical regular file path inside an approved import root.

    Raises:
        PathSafetyError: If the source is not a regular file or violates path
            policy. Suspicious hardlinks are denied because they can alias data
            from outside controlled import storage.
    """
    canonical = resolve_allowed_path(
        path,
        approved_roots=approved_roots or DEFAULT_IMPORT_ROOTS,
        base_dir=base_dir,
        must_exist=True,
    )
    _require_regular_file(canonical)
    _reject_suspicious_hardlink(canonical)
    return canonical


def validate_workspace_path(
    path: PathLike,
    *,
    approved_roots: Iterable[PathLike] | None = None,
    base_dir: PathLike | None = None,
) -> Path:
    """
    Validate a path for workspace/staging/generated artifact access.

    Args:
        path: Requested workspace-like path.
        approved_roots: Optional workspace allowlist roots.
        base_dir: Optional base directory for relative values.

    Returns:
        Canonical path inside a workspace, staging, or generated root.

    Raises:
        PathSafetyError: If the path is outside workspace policy.
    """
    return resolve_allowed_path(
        path,
        approved_roots=approved_roots or DEFAULT_WORKSPACE_ROOTS,
        base_dir=base_dir,
        must_exist=False,
    )


def _canonical_roots(roots: Iterable[PathLike], *, base_dir: Path) -> tuple[Path, ...]:
    """Return canonical allowed roots after rejecting overly broad boundaries."""
    canonical_roots: list[Path] = []
    for root in roots:
        canonical_root = canonicalize_path(root, base_dir=base_dir)
        _reject_forbidden_root(canonical_root)
        canonical_roots.append(canonical_root)

    if not canonical_roots:
        raise PathSafetyError("no approved roots configured")

    return tuple(canonical_roots)


def _is_relative_to(path: Path, root: Path) -> bool:
    """Use Path ancestry rather than string comparison for authorization."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_sensitive_components(path: Path) -> None:
    """Deny known secret-bearing filenames and credential-store directories."""
    lowered_parts = [part.lower() for part in path.parts]

    for part in lowered_parts:
        if part in _SENSITIVE_EXACT_COMPONENTS or part.startswith(".env."):
            raise PathSafetyError("path targets a sensitive secret or config location")
        if part == ".config":
            raise PathSafetyError("path targets a broad user configuration location")
        if any(hint in part for hint in _SENSITIVE_COMPONENT_HINTS):
            raise PathSafetyError("path targets a credential or browser data location")


def _reject_forbidden_root(root: Path) -> None:
    """Prevent callers from turning host-level directories into allowed roots."""
    if root in _FORBIDDEN_ROOTS:
        raise PathSafetyError("approved root is too broad")

    home = Path.home().resolve(strict=False)
    if root == home:
        raise PathSafetyError("approved root may not be the user home directory")

    if _is_relative_to(root, home) and root.name.lower() in _FORBIDDEN_HOME_CHILDREN:
        raise PathSafetyError("approved root targets a sensitive home directory")

    if root == _REPO_ROOT:
        raise PathSafetyError("approved root may not be the repository root")


def _reject_special_file(path: Path) -> None:
    """Deny sockets, FIFOs, devices, and other non-regular special files."""
    if not path.exists():
        return

    mode = path.stat().st_mode
    if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
        return

    raise PathSafetyError("path targets an unsafe filesystem object")


def _require_regular_file(path: Path) -> None:
    """Require import sources to be regular files, not directories or devices."""
    if not path.is_file():
        raise PathSafetyError("import source must be a regular file")


def _reject_suspicious_hardlink(path: Path) -> None:
    """Deny multi-linked import files because hardlinks can alias external data."""
    try:
        link_count = path.stat().st_nlink
    except OSError as exc:
        raise PathSafetyError("unable to inspect import source") from exc

    if link_count > 1:
        raise PathSafetyError("import source has suspicious hardlinks")


def _nearest_existing_parent(path: Path) -> Path:
    """Find the closest existing parent for a planned write target."""
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current
