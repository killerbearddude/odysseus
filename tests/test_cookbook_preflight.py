from __future__ import annotations

from pathlib import Path

import pytest

from services import cookbook_preflight as preflight
from services.cookbook_preflight import CookbookPreflightOptions, run_cookbook_preflight


def test_preflight_is_read_only_for_missing_cache_path(tmp_path: Path):
    # Regression guard: preflight must not create cache dirs, install packages, or mutate state.
    cache = tmp_path / "missing-cache"

    result = run_cookbook_preflight(CookbookPreflightOptions(model_cache_path=cache))

    assert "model_cache_path" in result.facts
    assert not cache.exists()


def test_preflight_reports_os_architecture_and_python_version(tmp_path: Path):
    # Regression guard: diagnostics need stable host facts before model setup starts.
    result = run_cookbook_preflight(CookbookPreflightOptions(model_cache_path=tmp_path))

    assert result.facts["os"]
    assert result.facts["architecture"]
    assert result.facts["python_version"]


def test_preflight_reports_missing_tmux_as_warning(monkeypatch, tmp_path: Path):
    # Regression guard: tmux-backed serving should fail with a clear warning, not a later opaque error.
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    result = run_cookbook_preflight(
        CookbookPreflightOptions(model_cache_path=tmp_path, require_tmux=True)
    )

    assert any("tmux" in warning.lower() for warning in result.warnings)


def test_preflight_reports_missing_docker_as_error_when_required(monkeypatch, tmp_path: Path):
    # Regression guard: Docker backend must report missing Docker before trying to start containers.
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    result = run_cookbook_preflight(
        CookbookPreflightOptions(model_cache_path=tmp_path, require_docker=True)
    )

    assert not result.ok
    assert any("docker" in error.lower() for error in result.errors)


def test_preflight_blocks_model_download_recommendation_in_offline_mode(monkeypatch, tmp_path: Path):
    # Regression guard: offline mode must block external model downloads before any network action.
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "true")

    result = run_cookbook_preflight(
        CookbookPreflightOptions(model_cache_path=tmp_path, model_download_requested=True)
    )

    assert not result.ok
    assert result.facts["offline_mode"] is True
    assert any("offline" in error.lower() for error in result.errors)
    assert "external model downloads" in result.recommended_next_action.lower()


def test_preflight_detects_unwritable_model_cache_path(tmp_path: Path):
    # Regression guard: model setup should not proceed into a path that cannot be a cache directory.
    cache_file = tmp_path / "not-a-directory"
    cache_file.write_text("not a directory")

    result = run_cookbook_preflight(CookbookPreflightOptions(model_cache_path=cache_file))

    assert not result.ok
    assert any("cache" in error.lower() for error in result.errors)


def test_preflight_returns_actionable_next_action_for_common_failures(monkeypatch, tmp_path: Path):
    # Regression guard: Cookbook failures should guide the operator to the next useful action.
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    result = run_cookbook_preflight(
        CookbookPreflightOptions(model_cache_path=tmp_path, require_docker=True)
    )

    assert "install docker" in result.recommended_next_action.lower()
