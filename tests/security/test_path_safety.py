"""
Security tests for canonical path-safety helpers.

These tests protect the reusable filesystem boundary that later tool policy,
staging, import, and sandbox enforcement will depend on.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from core.path_safety import (
    PathSafetyError,
    validate_import_source,
    validate_read_path,
    validate_workspace_path,
    validate_write_path,
)


def _make_roots(tmp_path: Path) -> dict[str, Path]:
    """Create isolated Odysseus-style roots for path-safety tests."""
    roots = {
        "workspaces": tmp_path / "data" / "workspaces",
        "uploads": tmp_path / "data" / "uploads",
        "imports": tmp_path / "data" / "imports",
        "staging": tmp_path / "data" / "staging",
        "generated": tmp_path / "data" / "generated",
        "backups": tmp_path / "data" / "backups",
    }
    for root in roots.values():
        root.mkdir(parents=True)
    return roots


def test_relative_traversal_is_denied(tmp_path: Path):
    # Prevents a path traversal regression where a relative path escapes an
    # approved root and lands elsewhere under the same temporary filesystem.
    roots = _make_roots(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("not allowed", encoding="utf-8")

    with pytest.raises(PathSafetyError):
        validate_read_path(
            Path("data") / "workspaces" / ".." / ".." / "outside.txt",
            approved_roots=[roots["workspaces"]],
            base_dir=tmp_path,
        )


def test_absolute_path_outside_approved_roots_is_denied(tmp_path: Path):
    # Ensures absolute paths do not bypass the approved-root policy.
    roots = _make_roots(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("not allowed", encoding="utf-8")

    with pytest.raises(PathSafetyError):
        validate_read_path(outside, approved_roots=[roots["workspaces"]], base_dir=tmp_path)


def test_symlink_escape_is_denied(tmp_path: Path):
    # Prevents a symlink inside an approved root from redirecting reads to a
    # target outside the approved root after canonicalization.
    roots = _make_roots(tmp_path)
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    link = roots["workspaces"] / "escape.txt"
    link.symlink_to(outside)

    with pytest.raises(PathSafetyError):
        validate_read_path(link, approved_roots=[roots["workspaces"]], base_dir=tmp_path)


def test_symlink_staying_inside_root_is_allowed(tmp_path: Path):
    # Allows safe symlinks only when the resolved final target remains inside the
    # approved root; this distinguishes safe normalization from blanket symlink
    # rejection.
    roots = _make_roots(tmp_path)
    target = roots["workspaces"] / "target.txt"
    target.write_text("allowed", encoding="utf-8")
    link = roots["workspaces"] / "link.txt"
    link.symlink_to(target)

    assert validate_read_path(link, approved_roots=[roots["workspaces"]], base_dir=tmp_path) == target


def test_secret_files_are_denied_even_under_approved_root(tmp_path: Path):
    # Prevents accidental direct reads of copied app secrets under otherwise
    # approved storage locations.
    roots = _make_roots(tmp_path)
    env_file = roots["workspaces"] / ".env"
    app_key = roots["workspaces"] / ".app_key"
    env_file.write_text("TOKEN=secret", encoding="utf-8")
    app_key.write_text("secret", encoding="utf-8")

    with pytest.raises(PathSafetyError):
        validate_read_path(env_file, approved_roots=[roots["workspaces"]], base_dir=tmp_path)
    with pytest.raises(PathSafetyError):
        validate_read_path(app_key, approved_roots=[roots["workspaces"]], base_dir=tmp_path)


def test_home_ssh_key_is_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # Guards against user-home credential access even if a future caller passes
    # an unsafe broad root by mistake.
    fake_home = tmp_path / "home" / "daniel"
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    key = ssh_dir / "id_rsa"
    key.write_text("private key", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))

    with pytest.raises(PathSafetyError):
        validate_read_path(key, approved_roots=[tmp_path / "home"], base_dir=tmp_path)


def test_fifo_is_denied_when_platform_supports_it(tmp_path: Path):
    # Prevents tools from reading special files that can block, stream, or expose
    # host resources instead of regular content.
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is unavailable on this platform")

    roots = _make_roots(tmp_path)
    fifo = roots["imports"] / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(PathSafetyError):
        validate_read_path(fifo, approved_roots=[roots["imports"]], base_dir=tmp_path)


def test_socket_is_denied_when_platform_supports_unix_sockets(tmp_path: Path):
    # Prevents filesystem-looking socket paths from being treated as safe files.
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets are unavailable on this platform")

    roots = _make_roots(tmp_path)
    socket_path = roots["imports"] / "service.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(socket_path))
        with pytest.raises(PathSafetyError):
            validate_read_path(socket_path, approved_roots=[roots["imports"]], base_dir=tmp_path)
    finally:
        sock.close()


def test_regular_file_under_imports_is_allowed_for_import(tmp_path: Path):
    # Confirms legitimate import quarantine files remain usable after adding
    # special-file and sensitive-path checks.
    roots = _make_roots(tmp_path)
    source = roots["imports"] / "document.txt"
    source.write_text("content", encoding="utf-8")

    assert validate_import_source(source, approved_roots=[roots["imports"]], base_dir=tmp_path) == source


def test_write_outside_workspace_or_staging_is_denied(tmp_path: Path):
    # Prevents write-capable tools from creating files in read-only or unrelated
    # paths that happen to exist near approved storage.
    roots = _make_roots(tmp_path)
    outside_target = tmp_path / "data" / "backups" / "unsafe.txt"

    with pytest.raises(PathSafetyError):
        validate_write_path(
            outside_target,
            approved_roots=[roots["workspaces"], roots["staging"]],
            base_dir=tmp_path,
        )


def test_write_inside_staging_is_allowed(tmp_path: Path):
    # Ensures the future generated-action review flow has a valid staging target
    # while keeping writes constrained to approved roots.
    roots = _make_roots(tmp_path)
    target = roots["staging"] / "review.txt"

    assert validate_write_path(target, approved_roots=[roots["staging"]], base_dir=tmp_path) == target


def test_commonprefix_trap_is_denied(tmp_path: Path):
    # Prevents the classic sibling-prefix bypass where an unsafe path shares a
    # textual prefix with the allowed root but is not actually beneath it.
    allowed = tmp_path / "root"
    evil = tmp_path / "root_evil"
    allowed.mkdir()
    evil.mkdir()
    target = evil / "payload.txt"
    target.write_text("not allowed", encoding="utf-8")

    with pytest.raises(PathSafetyError):
        validate_read_path(target, approved_roots=[allowed], base_dir=tmp_path)


def test_workspace_path_uses_workspace_roots(tmp_path: Path):
    # Confirms workspace validation is separately constrainable from broader read
    # roots so later tool routes can apply more specific policies.
    roots = _make_roots(tmp_path)
    workspace_target = roots["workspaces"] / "project" / "file.txt"

    assert validate_workspace_path(
        workspace_target,
        approved_roots=[roots["workspaces"]],
        base_dir=tmp_path,
    ) == workspace_target
