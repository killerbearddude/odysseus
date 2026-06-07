"""
Security tests for file-tool confinement primitives.

This file intentionally tests the central path-safety helper rather than a live
route. Route-level enforcement should be wired in later PRs once the reusable
boundary is stable and covered by regression tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.path_safety import PathSafetyError, validate_import_source, validate_read_path, validate_write_path


def _controlled_storage(tmp_path: Path) -> dict[str, Path]:
    """Create minimal controlled storage roots for file-tool confinement tests."""
    storage = {
        "workspace": tmp_path / "data" / "workspaces" / "default",
        "staging": tmp_path / "data" / "staging",
        "imports": tmp_path / "data" / "imports",
    }
    for path in storage.values():
        path.mkdir(parents=True)
    return storage


def test_file_tool_read_is_confined_to_declared_root(tmp_path: Path):
    # Prevents file tools from reading arbitrary absolute paths when a narrower
    # tool policy has declared only one workspace root.
    storage = _controlled_storage(tmp_path)
    allowed_file = storage["workspace"] / "note.txt"
    allowed_file.write_text("allowed", encoding="utf-8")

    assert validate_read_path(allowed_file, approved_roots=[storage["workspace"]], base_dir=tmp_path) == allowed_file


def test_file_tool_read_denies_sibling_directory_with_same_prefix(tmp_path: Path):
    # Protects against prefix-based authorization mistakes such as allowing
    # /workspace_evil when /workspace is the real approved root.
    storage = _controlled_storage(tmp_path)
    sibling = storage["workspace"].parent / f"{storage['workspace'].name}_evil"
    sibling.mkdir()
    secret = sibling / "secret.txt"
    secret.write_text("not allowed", encoding="utf-8")

    with pytest.raises(PathSafetyError):
        validate_read_path(secret, approved_roots=[storage["workspace"]], base_dir=tmp_path)


def test_file_tool_write_denies_symlinked_parent_escape(tmp_path: Path):
    # Prevents writes through an approved-looking symlinked directory that
    # resolves outside controlled staging/workspace storage.
    storage = _controlled_storage(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = storage["staging"] / "linked"
    link_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathSafetyError):
        validate_write_path(link_dir / "payload.txt", approved_roots=[storage["staging"]], base_dir=tmp_path)


def test_file_tool_write_allows_new_file_in_workspace(tmp_path: Path):
    # Confirms the helper supports normal new-file creation inside a declared
    # workspace without requiring the target file to exist first.
    storage = _controlled_storage(tmp_path)
    target = storage["workspace"] / "draft.md"

    assert validate_write_path(target, approved_roots=[storage["workspace"]], base_dir=tmp_path) == target


def test_file_tool_import_rejects_directory(tmp_path: Path):
    # Prevents import paths from treating directories as regular file inputs,
    # which could lead to recursive ingestion or unexpected filesystem walking.
    storage = _controlled_storage(tmp_path)

    with pytest.raises(PathSafetyError):
        validate_import_source(storage["imports"], approved_roots=[storage["imports"]], base_dir=tmp_path)


def test_file_tool_import_rejects_hardlinked_file(tmp_path: Path):
    # Hardlinks can make controlled import paths alias data created elsewhere.
    # Denying multi-linked import files keeps provenance conservative until a
    # later copy-into-storage flow records hashes and metadata.
    storage = _controlled_storage(tmp_path)
    source = storage["imports"] / "source.txt"
    source.write_text("content", encoding="utf-8")
    linked = storage["imports"] / "linked.txt"

    try:
        linked.hardlink_to(source)
    except OSError:
        pytest.skip("hardlinks are unavailable on this filesystem")

    with pytest.raises(PathSafetyError):
        validate_import_source(linked, approved_roots=[storage["imports"]], base_dir=tmp_path)
