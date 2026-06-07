"""
Read-only diagnostics collection for Odysseus operators.

This module gathers a small, redacted status snapshot for administrators and
support bundles. It intentionally avoids telemetry, arbitrary shell execution,
and privileged log scraping. Only exact allowlisted commands are executed, and
missing optional tools such as Git or Docker are reported gracefully.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from core.offline_mode import is_offline_mode
except Exception:  # pragma: no cover - compatibility fallback for old branches.
    def is_offline_mode() -> bool:
        """Return offline-mode status from the environment."""
        return os.getenv("ODYSSEUS_OFFLINE_MODE", "false").lower() in {"1", "true", "yes", "on"}

try:
    from core.tool_registry import get_registered_tool_policies
except Exception:  # pragma: no cover - compatibility fallback for old branches.
    def get_registered_tool_policies() -> Mapping[str, Any]:
        """Return an empty registry summary when the tool registry is unavailable."""
        return {}

try:
    from services.tool_runner import LocalToolRunner
except Exception:  # pragma: no cover - compatibility fallback for old branches.
    LocalToolRunner = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CommandResult:
    """Result from an allowlisted diagnostic command."""

    ok: bool
    command: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    unavailable: bool = False
    timed_out: bool = False
    exit_code: int | None = None


_ALLOWED_COMMANDS: set[tuple[str, ...]] = {
    ("git", "rev-parse", "--short", "HEAD"),
    ("git", "status", "--short"),
    ("docker", "--version"),
    ("docker", "compose", "ps", "--format", "json"),
}


class DiagnosticsError(RuntimeError):
    """Raised when a diagnostics request violates the read-only command policy."""


def _run_allowlisted_command(command: Iterable[str], *, cwd: Path, timeout_seconds: float = 2.0) -> CommandResult:
    """
    Run one exact allowlisted command without using a shell.

    Args:
        command: Command argv tuple to execute.
        cwd: Repository directory to run the command from.
        timeout_seconds: Maximum command runtime.

    Returns:
        CommandResult with stdout/stderr bounded and optional-tool failures
        represented as data instead of exceptions.

    Raises:
        DiagnosticsError: If the command is not in the exact allowlist.
    """
    argv = tuple(str(part) for part in command)
    if argv not in _ALLOWED_COMMANDS:
        raise DiagnosticsError("diagnostics command is not allowlisted")

    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(ok=False, command=argv, unavailable=True, stderr="command unavailable")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            ok=False,
            command=argv,
            stdout=(exc.stdout or "")[:4096] if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "")[:4096] if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )

    return CommandResult(
        ok=completed.returncode == 0,
        command=argv,
        stdout=completed.stdout[:4096],
        stderr=completed.stderr[:4096],
        exit_code=completed.returncode,
    )


def _command_dict(result: CommandResult) -> dict[str, Any]:
    """Convert a command result to JSON-compatible diagnostics output."""
    return {
        "ok": result.ok,
        "command": list(result.command),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "unavailable": result.unavailable,
        "timed_out": result.timed_out,
        "exit_code": result.exit_code,
    }


def _git_summary(repo_root: Path) -> dict[str, Any]:
    """Return Git commit and dirty-state information when Git is available."""
    commit = _run_allowlisted_command(("git", "rev-parse", "--short", "HEAD"), cwd=repo_root)
    status = _run_allowlisted_command(("git", "status", "--short"), cwd=repo_root)
    return {
        "available": commit.ok or status.ok,
        "commit": commit.stdout.strip() if commit.ok else None,
        "dirty": bool(status.stdout.strip()) if status.ok else None,
        "commit_command": _command_dict(commit),
        "status_command": _command_dict(status),
    }


def _docker_summary(repo_root: Path) -> dict[str, Any]:
    """Return Docker availability without failing when Docker is not installed."""
    version = _run_allowlisted_command(("docker", "--version"), cwd=repo_root)
    compose_ps = _run_allowlisted_command(("docker", "compose", "ps", "--format", "json"), cwd=repo_root)
    return {
        "available": version.ok,
        "version": version.stdout.strip() if version.ok else None,
        "version_command": _command_dict(version),
        "compose_ps_command": _command_dict(compose_ps),
    }


def _sqlite_status(path: Path) -> dict[str, Any]:
    """Return a minimal SQLite health result without reading table contents."""
    if not path.exists():
        return {"path": str(path), "exists": False, "ok": False}
    try:
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA quick_check")
        return {"path": str(path), "exists": True, "ok": True}
    except sqlite3.Error as exc:
        return {"path": str(path), "exists": True, "ok": False, "error": type(exc).__name__}


def _directory_status(path: Path) -> dict[str, Any]:
    """Return existence and item count for an optional service directory."""
    if not path.exists():
        return {"path": str(path), "exists": False, "item_count": 0}
    if not path.is_dir():
        return {"path": str(path), "exists": True, "is_dir": False, "item_count": 0}
    try:
        count = sum(1 for _ in path.iterdir())
    except OSError:
        count = None
    return {"path": str(path), "exists": True, "is_dir": True, "item_count": count}


def _disk_usage(path: Path) -> dict[str, Any]:
    """Return disk usage for the filesystem containing the repository."""
    usage = shutil.disk_usage(path)
    return {"total": usage.total, "used": usage.used, "free": usage.free}


def _tool_policy_summary() -> dict[str, Any]:
    """Return a safe summary of the static tool-policy registry."""
    policies = get_registered_tool_policies()
    risk_counts: dict[str, int] = {}
    enabled_count = 0
    for policy in policies.values():
        risk = getattr(policy, "risk", "unknown")
        risk_counts[str(risk)] = risk_counts.get(str(risk), 0) + 1
        if getattr(policy, "enabled", False):
            enabled_count += 1
    return {
        "available": True,
        "registered_count": len(policies),
        "enabled_count": enabled_count,
        "risk_counts": risk_counts,
    }


def _runner_summary() -> dict[str, Any]:
    """Return sandbox runner availability without executing a command."""
    return {
        "local_runner_available": LocalToolRunner is not None,
        "docker_runner_available": False,
        "notes": "local runner abstraction only; no Docker runner in this diagnostics layer",
    }


def _audit_summary(repo_root: Path) -> dict[str, Any]:
    """Return audit-store status without exporting raw audit contents."""
    audit_path = repo_root / "data" / "tool_audit.sqlite"
    status = _sqlite_status(audit_path)
    event_count: int | None = None
    if status.get("ok"):
        try:
            with sqlite3.connect(audit_path) as conn:
                row = conn.execute("SELECT COUNT(*) FROM tool_audit_events").fetchone()
                event_count = int(row[0]) if row else 0
        except sqlite3.Error:
            event_count = None
    return {**status, "event_count": event_count, "raw_events_exported": False}


def collect_diagnostics(*, repo_root: Path | None = None) -> dict[str, Any]:
    """
    Collect a redacted, read-only diagnostics snapshot.

    Args:
        repo_root: Repository root to inspect. Defaults to the current working
            directory so tests and CLI callers can provide an isolated fixture.

    Returns:
        JSON-compatible diagnostics dictionary safe for admin inspection and
        support bundle inclusion.
    """
    root = (repo_root or Path.cwd()).resolve()
    deployment_mode = os.getenv("ODYSSEUS_DEPLOYMENT_MODE", "local")
    now = datetime.now(timezone.utc).isoformat()

    data_dir = root / "data"
    diagnostics = {
        "generated_at": now,
        "app": {
            "name": "odysseus",
            "version": os.getenv("ODYSSEUS_VERSION", "0.0.0-alpha"),
            "git": _git_summary(root),
        },
        "config": {
            "deployment_mode": deployment_mode,
            "offline_mode": is_offline_mode(),
            "auth_enabled": os.getenv("AUTH_ENABLED", "true").lower() not in {"0", "false", "no", "off"},
        },
        "runtime": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "docker": _docker_summary(root),
        "database": _sqlite_status(data_dir / "app.db"),
        "chromadb": _directory_status(data_dir / "chroma"),
        "searxng": {"configured": bool(os.getenv("SEARXNG_URL")), "status": "not_probed"},
        "ntfy": {"configured": bool(os.getenv("NTFY_URL")), "status": "not_probed"},
        "providers": {"probe_summary": "not_probed", "offline_mode": is_offline_mode()},
        "model_serving": {"status": "not_probed"},
        "background_jobs": {"status": "not_probed"},
        "email_poller": {"status": "not_probed"},
        "disk_usage": _disk_usage(root),
        "recent_errors": [],
        "config_warnings": build_config_warnings(root),
        "tool_policy": _tool_policy_summary(),
        "sandbox_runner": _runner_summary(),
        "audit": _audit_summary(root),
    }
    return diagnostics


def build_config_warnings(repo_root: Path) -> list[str]:
    """Return non-secret configuration warnings for operator diagnostics."""
    warnings: list[str] = []
    if is_offline_mode():
        warnings.append("offline mode is enabled; external integrations should be blocked")
    if (repo_root / ".env").exists():
        warnings.append(".env exists locally and is excluded from support bundles")
    if (repo_root / ".app_key").exists():
        warnings.append(".app_key exists locally and is excluded from support bundles")
    return warnings


def diagnostics_to_json(diagnostics: Mapping[str, Any]) -> str:
    """Serialize diagnostics with stable formatting for support bundles."""
    return json.dumps(diagnostics, indent=2, sort_keys=True) + "\n"
