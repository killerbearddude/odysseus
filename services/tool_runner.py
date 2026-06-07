"""
Sandbox runner abstraction for Odysseus tool execution.

This module defines the first safe execution boundary for reviewed local tool
runs. It does not attempt to provide a full container or kernel sandbox; instead
it creates a fail-closed interface with constrained working directories,
required timeouts, bounded output, environment allowlisting, and structured
responses. Higher-level tool policy, staging, confirmation, and audit code can
call this layer without letting model-provided arguments define execution rules.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from core.audit_redaction import redact_secret_like_values
from core.path_safety import PathSafetyError, validate_read_path, validate_workspace_path, validate_write_path


class ToolRunnerError(ValueError):
    """Raised when a runner request violates sandbox runner policy."""


MAX_TIMEOUT_SECONDS = 30
MAX_OUTPUT_LIMIT_BYTES = 1024 * 1024

# Runner working directories are deliberately narrower than generic workspace
# paths. Generated artifacts may be readable elsewhere, but executable working
# directories should stay in human-owned workspaces or staging areas.
RUNNER_WORKING_ROOTS: tuple[str, ...] = (
    "data/workspaces",
    "data/staging",
)

RUNNER_WRITE_ROOTS: tuple[str, ...] = (
    "data/workspaces",
    "data/staging",
)

# Only boring locale/path values are inherited. Provider keys, app secrets,
# session tokens, and credentials are intentionally not copied from os.environ.
SAFE_INHERITED_ENV_KEYS: frozenset[str] = frozenset({
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
})

SAFE_EXPLICIT_ENV_KEYS: frozenset[str] = SAFE_INHERITED_ENV_KEYS | frozenset({
    "ODYSSEUS_RUNNER_MODE",
    "ODYSSEUS_RUNNER_SAFE_FLAG",
})

SECRET_ENV_KEY_FRAGMENTS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "app_key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "secret",
    "session",
    "token",
)

SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

NETWORK_COMMANDS: frozenset[str] = frozenset({
    "curl",
    "wget",
    "nc",
    "netcat",
    "nmap",
    "ssh",
    "scp",
    "sftp",
    "telnet",
    "ping",
})

NETWORK_ARGUMENT_HINTS: tuple[str, ...] = (
    "http://",
    "https://",
    "ftp://",
    "socket",
    "urllib",
    "requests",
    "http.client",
)


@dataclass(frozen=True)
class RunnerRequest:
    """
    Declarative request for a constrained local tool run.

    The request is intentionally explicit. Callers must provide timeout and
    output limits, and may not rely on inherited process environment or implicit
    current working directories.
    """

    command: str
    args: tuple[str, ...] = field(default_factory=tuple)
    working_dir: str | os.PathLike[str] = "data/staging"
    environment: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float | None = None
    output_limit_bytes: int | None = None
    network_allowed: bool = False
    read_paths: tuple[str, ...] = field(default_factory=tuple)
    write_paths: tuple[str, ...] = field(default_factory=tuple)
    user_id: str | None = None
    decision_id: str | None = None
    shell: bool = False
    reviewed_shell: bool = False


@dataclass(frozen=True)
class RunnerResponse:
    """
    Structured result from a constrained local tool run.

    Stdout and stderr are always bounded and redacted before they are returned
    so callers can store or display runner results without leaking provider keys
    or other secret-looking output by default.
    """

    ok: bool
    exit_code: int | None
    stdout_excerpt: str
    stderr_excerpt: str
    duration_ms: int
    files_created: tuple[str, ...] = field(default_factory=tuple)
    files_modified: tuple[str, ...] = field(default_factory=tuple)
    network_attempts: tuple[str, ...] = field(default_factory=tuple)
    killed_for_timeout: bool = False


class LocalToolRunner:
    """
    Safe local development runner for reviewed tool actions.

    This runner is not a full sandbox. It is a defensive local abstraction that
    enforces the controls available without Docker or OS policy: path allowlists,
    timeout, output limits, no secret environment inheritance, process-group
    cleanup on timeout, and fail-closed request validation.
    """

    def __init__(self, *, repo_root: str | os.PathLike[str] | None = None) -> None:
        """
        Initialize a local runner.

        Args:
            repo_root: Repository root used to resolve Odysseus data roots. Tests
                can pass a temporary root to avoid touching real application data.
        """
        self.repo_root = Path(repo_root).resolve(strict=False) if repo_root else Path.cwd().resolve(strict=False)

    def run(self, request: RunnerRequest) -> RunnerResponse:
        """
        Execute a reviewed local command under runner constraints.

        Args:
            request: Declarative runner request.

        Returns:
            Bounded and redacted structured response.

        Raises:
            ToolRunnerError: If the request violates runner policy before launch.
        """
        self._validate_request(request)
        working_dir = self._validate_working_dir(request.working_dir)
        self._validate_requested_paths(request)
        environment = self._build_environment(request.environment)

        before = _snapshot_files(working_dir)
        started = time.monotonic()
        killed_for_timeout = False
        exit_code: int | None
        stdout_bytes = b""
        stderr_bytes = b""

        argv: Sequence[str] | str
        if request.shell:
            argv = " ".join([request.command, *request.args])
        else:
            argv = (request.command, *request.args)

        process = subprocess.Popen(
            argv,
            cwd=working_dir,
            env=environment,
            shell=request.shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=request.timeout_seconds)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            killed_for_timeout = True
            _kill_process_group(process)
            stdout_bytes, stderr_bytes = process.communicate()
            exit_code = process.returncode

        duration_ms = int((time.monotonic() - started) * 1000)
        after = _snapshot_files(working_dir)
        created, modified = _diff_snapshots(before, after)

        return RunnerResponse(
            ok=(exit_code == 0 and not killed_for_timeout),
            exit_code=exit_code,
            stdout_excerpt=_bounded_redacted_text(stdout_bytes, request.output_limit_bytes or 0),
            stderr_excerpt=_bounded_redacted_text(stderr_bytes, request.output_limit_bytes or 0),
            duration_ms=duration_ms,
            files_created=created,
            files_modified=modified,
            network_attempts=_network_attempt_hints(request),
            killed_for_timeout=killed_for_timeout,
        )

    def _validate_request(self, request: RunnerRequest) -> None:
        """Fail closed for missing limits, shell bypasses, and network-like requests."""
        if not request.command or not str(request.command).strip():
            raise ToolRunnerError("runner command is required")

        if request.timeout_seconds is None:
            raise ToolRunnerError("runner timeout is required")
        if request.timeout_seconds <= 0 or request.timeout_seconds > MAX_TIMEOUT_SECONDS:
            raise ToolRunnerError("runner timeout is outside allowed bounds")

        if request.output_limit_bytes is None:
            raise ToolRunnerError("runner output limit is required")
        if request.output_limit_bytes <= 0 or request.output_limit_bytes > MAX_OUTPUT_LIMIT_BYTES:
            raise ToolRunnerError("runner output limit is outside allowed bounds")

        if request.shell and not request.reviewed_shell:
            raise ToolRunnerError("shell execution requires a reviewed shell request")

        if not request.network_allowed and _network_attempt_hints(request):
            raise ToolRunnerError("network-looking command denied by runner policy")

    def _validate_working_dir(self, working_dir: str | os.PathLike[str]) -> Path:
        """Validate and return a real runner working directory under allowed roots."""
        try:
            resolved = validate_workspace_path(
                working_dir,
                approved_roots=RUNNER_WORKING_ROOTS,
                base_dir=self.repo_root,
            )
        except PathSafetyError as exc:
            raise ToolRunnerError(f"runner working directory denied: {exc}") from exc

        if not resolved.exists() or not resolved.is_dir():
            raise ToolRunnerError("runner working directory must exist")

        return resolved

    def _validate_requested_paths(self, request: RunnerRequest) -> None:
        """Validate declared read/write paths through the canonical path helper."""
        for path in request.read_paths:
            try:
                validate_read_path(path, base_dir=self.repo_root)
            except PathSafetyError as exc:
                raise ToolRunnerError(f"runner read path denied: {exc}") from exc

        for path in request.write_paths:
            try:
                validate_write_path(
                    path,
                    approved_roots=RUNNER_WRITE_ROOTS,
                    base_dir=self.repo_root,
                )
            except PathSafetyError as exc:
                raise ToolRunnerError(f"runner write path denied: {exc}") from exc

    def _build_environment(self, explicit_environment: Mapping[str, str]) -> dict[str, str]:
        """Build an allowlisted environment without inherited application secrets."""
        env: dict[str, str] = {}
        for key in SAFE_INHERITED_ENV_KEYS:
            value = os.environ.get(key)
            if value is not None and not _is_secret_env_value(key, value):
                env[key] = value

        for key, value in explicit_environment.items():
            key = str(key)
            value = str(value)
            if key not in SAFE_EXPLICIT_ENV_KEYS:
                raise ToolRunnerError(f"environment variable is not allowlisted: {key}")
            if _is_secret_env_value(key, value):
                raise ToolRunnerError("environment contains secret-looking value")
            env[key] = value

        return env


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a runner process group, falling back to process.kill when needed."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        process.kill()


def _snapshot_files(root: Path) -> dict[Path, tuple[int, int]]:
    """Capture a lightweight file snapshot under the runner working directory."""
    snapshot: dict[Path, tuple[int, int]] = {}
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                stat_result = path.stat()
                snapshot[path.relative_to(root)] = (stat_result.st_size, stat_result.st_mtime_ns)
        except OSError:
            continue
    return snapshot


def _diff_snapshots(
    before: Mapping[Path, tuple[int, int]],
    after: Mapping[Path, tuple[int, int]],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return files created and modified between two snapshots."""
    created = sorted(str(path) for path in after.keys() - before.keys())
    modified = sorted(
        str(path)
        for path in after.keys() & before.keys()
        if after[path] != before[path]
    )
    return tuple(created), tuple(modified)


def _bounded_redacted_text(raw: bytes, limit: int) -> str:
    """Decode, truncate, and redact command output for safe structured responses."""
    bounded = raw[:limit]
    text = bounded.decode("utf-8", errors="replace")
    if len(raw) > len(bounded):
        text += "…[truncated]"
    return redact_secret_like_values(text)


def _is_secret_env_value(key: str, value: str) -> bool:
    """Return True when an env key or value looks like a credential."""
    normalized_key = key.lower().replace("-", "_")
    if any(fragment in normalized_key for fragment in SECRET_ENV_KEY_FRAGMENTS):
        return True
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def _network_attempt_hints(request: RunnerRequest) -> tuple[str, ...]:
    """Detect obvious network command hints without claiming firewall enforcement."""
    hints: list[str] = []
    command_name = Path(str(request.command)).name.lower()
    if command_name in NETWORK_COMMANDS:
        hints.append(command_name)

    haystack = " ".join([str(request.command), *(str(arg) for arg in request.args)]).lower()
    for hint in NETWORK_ARGUMENT_HINTS:
        if hint in haystack:
            hints.append(hint)

    return tuple(dict.fromkeys(hints))
