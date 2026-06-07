"""
Security tests for admin diagnostics collection.

These tests ensure diagnostics remain read-only, admin-gated at the router, and
safe when optional host tools such as Git or Docker are missing.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.routing import APIRoute

from routes.admin_diagnostics_routes import setup_admin_diagnostics_routes
from services import diagnostics as diagnostics_service
from services.diagnostics import CommandResult, collect_diagnostics


def test_diagnostics_include_offline_and_deployment_mode(monkeypatch, tmp_path: Path):
    # Operators need offline/deployment status in diagnostics without telemetry.
    monkeypatch.setenv("ODYSSEUS_OFFLINE_MODE", "true")
    monkeypatch.setenv("ODYSSEUS_DEPLOYMENT_MODE", "private-proxy")

    data = collect_diagnostics(repo_root=tmp_path)

    assert data["config"]["offline_mode"] is True
    assert data["config"]["deployment_mode"] == "private-proxy"


def test_diagnostics_include_tool_policy_audit_and_runner_status(tmp_path: Path):
    # Diagnostics should summarize policy/audit/sandbox state, not raw data.
    data = collect_diagnostics(repo_root=tmp_path)

    assert data["tool_policy"]["registered_count"] >= 0
    assert "local_runner_available" in data["sandbox_runner"]
    assert data["audit"]["raw_events_exported"] is False


def test_diagnostics_handle_missing_docker_and_git_gracefully(monkeypatch, tmp_path: Path):
    # Missing optional binaries should be diagnostics data, not route failures.
    def fake_run(command, *, cwd, timeout_seconds=2.0):
        return CommandResult(ok=False, command=tuple(command), unavailable=True, stderr="missing")

    monkeypatch.setattr(diagnostics_service, "_run_allowlisted_command", fake_run)

    data = collect_diagnostics(repo_root=tmp_path)

    assert data["docker"]["available"] is False
    assert data["app"]["git"]["available"] is False


def test_diagnostics_route_requires_admin_dependency():
    # Regression guard: the diagnostics route must stay behind require_admin.
    router = setup_admin_diagnostics_routes()
    routes = [route for route in router.routes if isinstance(route, APIRoute)]
    diagnostics_route = next(route for route in routes if route.path == "/api/admin/diagnostics")

    dependency_calls = {
        getattr(dep, "call", None) or getattr(dep, "dependency", None)
        for dep in diagnostics_route.dependant.dependencies
    }
    dependency_names = {
        getattr(call, "__name__", "")
        for call in dependency_calls
        if call is not None
    }

    assert "require_admin" in dependency_names
