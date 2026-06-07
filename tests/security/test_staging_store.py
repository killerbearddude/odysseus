"""Security tests for staged artifact filesystem confinement."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from services.staging_store import StagingStore, StagingStoreError


def test_staged_artifact_ids_are_server_generated(tmp_path: Path):
    # Prevents callers from choosing filenames or paths that could bypass review
    # storage. IDs should be opaque server-generated UUID hex strings.
    store = StagingStore(tmp_path / "staging")

    first = store.stage_artifact("generated-script", "echo first", extension=".sh")
    second = store.stage_artifact("generated-script", "echo second", extension=".sh")

    assert first.artifact_id != second.artifact_id
    assert len(first.artifact_id) == 32
    assert all(ch in "0123456789abcdef" for ch in first.artifact_id)
    assert first.path.parent == store.generated_script_dir()


def test_staged_artifact_cannot_escape_with_traversal_type(tmp_path: Path):
    # Unknown artifact categories must fail closed so category names cannot be
    # abused as caller-controlled path fragments.
    store = StagingStore(tmp_path / "staging")

    with pytest.raises(StagingStoreError):
        store.stage_artifact("generated-script/../../escape", "echo bad", extension=".sh")


def test_staged_artifact_cannot_use_unsafe_extension(tmp_path: Path):
    # Extensions are part of the generated filename, so reject separators and
    # traversal there too.
    store = StagingStore(tmp_path / "staging")

    with pytest.raises(StagingStoreError):
        store.stage_artifact("generated-script", "echo bad", extension="../evil")


def test_staging_directory_symlink_escape_is_denied(tmp_path: Path):
    # Prevents an attacker-controlled symlink under data/staging from redirecting
    # generated artifacts into an arbitrary host directory.
    staging_root = tmp_path / "staging"
    outside = tmp_path / "outside"
    store = StagingStore(staging_root)
    outside.mkdir()

    generated_dir = staging_root / "generated-scripts"
    generated_dir.rmdir()
    generated_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(StagingStoreError):
        store.stage_artifact("generated-script", "echo bad", extension=".sh")


def test_stage_artifact_writes_atomically_and_does_not_overwrite_existing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Prevents replacing a previously reviewed artifact with different content
    # under the same server-generated ID.
    store = StagingStore(tmp_path / "staging")
    fixed_id = "a" * 32
    monkeypatch.setattr(store, "generate_artifact_id", lambda: fixed_id)

    first = store.stage_artifact("file-patch", "patch one", extension=".patch")
    assert first.path.read_text() == "patch one"

    with pytest.raises(StagingStoreError):
        store.stage_artifact("file-patch", "patch two", extension=".patch")


def test_rejected_artifact_moves_to_rejected_area(tmp_path: Path):
    # Rejected generated content should remain separated from active review
    # queues so later tooling cannot accidentally approve it.
    store = StagingStore(tmp_path / "staging")
    artifact = store.stage_artifact("email-draft", "hello", extension=".eml")

    rejected = store.reject_artifact("email-draft", artifact.artifact_id)

    assert rejected.rejected is True
    assert not artifact.path.exists()
    assert rejected.path.exists()
    assert rejected.path.parent == store.root / "rejected"
    assert rejected.path.read_text() == "hello"


def test_audit_hook_receives_staging_events(tmp_path: Path):
    # Provides a low-risk hook for later audit integration without introducing a
    # circular dependency from staging storage into audit storage.
    events: list[tuple[str, dict[str, object]]] = []
    store = StagingStore(tmp_path / "staging", audit_hook=lambda event, metadata: events.append((event, metadata)))

    artifact = store.stage_artifact("model-config-change", "config", extension=".json")

    assert events
    assert events[0][0] == "tool_staged"
    assert events[0][1]["artifact_id"] == artifact.artifact_id


def test_store_rejects_root_symlink(tmp_path: Path):
    # The staging root itself must not be a symlink because all child checks rely
    # on a stable root path.
    outside = tmp_path / "outside"
    outside.mkdir()
    staging_root = tmp_path / "staging"
    staging_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(StagingStoreError):
        StagingStore(staging_root)
