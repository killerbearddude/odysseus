"""
Redacted local support-bundle creation for Odysseus.

The support bundle is an operator-triggered, read-only zip archive intended for
local debugging. It includes diagnostics and redacted summaries, but excludes
raw secrets, runtime databases, uploads, private documents, email contents, and
large unbounded files.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

try:
    from core.audit_redaction import redact_secret_like_values
except Exception:  # pragma: no cover - compatibility fallback for old branches.
    def redact_secret_like_values(value: object) -> str:
        """Fallback redactor used only when the audit module is unavailable."""
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
        return re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=[REDACTED]", text)

from services.diagnostics import collect_diagnostics, diagnostics_to_json


SECRET_LINE_RE = re.compile(
    r"(?im)^(?P<key>[A-Z0-9_]*(?:API_KEY|TOKEN|PASSWORD|SECRET|APP_KEY|SESSION)[A-Z0-9_]*)\s*=\s*(?P<value>.*)$"
)
BEARER_RE = re.compile(r"(?i)Authorization:\s*Bearer\s+[^\s]+")
COOKIE_RE = re.compile(r"(?i)(Set-Cookie:|Cookie:)\s*[^\n]+")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")


class SupportBundleError(RuntimeError):
    """Raised when support-bundle creation would violate export policy."""


@dataclass(frozen=True)
class SupportBundleOptions:
    """Configuration for creating a redacted support bundle."""

    output_path: Path
    repo_root: Path = Path.cwd()
    allowed_output_roots: tuple[Path, ...] = ()
    max_log_bytes: int = 64 * 1024
    include_logs: bool = True

    def __post_init__(self) -> None:
        """Normalize path-like constructor values in a frozen dataclass."""
        object.__setattr__(self, "output_path", Path(self.output_path))
        object.__setattr__(self, "repo_root", Path(self.repo_root))
        object.__setattr__(
            self,
            "allowed_output_roots",
            tuple(Path(root) for root in self.allowed_output_roots),
        )


def redact_diagnostics_text(value: object) -> str:
    """
    Redact secret-like values from diagnostic text before bundle storage.

    Args:
        value: Text or bytes from logs/config/command output.

    Returns:
        Redacted text with bearer tokens, cookies, private keys, and common
        key-value secrets replaced by explicit markers.
    """
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = PRIVATE_KEY_RE.sub("[REDACTED:private_key]", text)
    text = BEARER_RE.sub("Authorization: Bearer [REDACTED]", text)
    text = COOKIE_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = SECRET_LINE_RE.sub(lambda m: f"{m.group('key')}=[REDACTED]", text)
    return redact_secret_like_values(text)


def _is_relative_to(child: Path, parent: Path) -> bool:
    """Return True if child is within parent after resolution."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_output_path(output_path: Path, *, allowed_output_roots: Iterable[Path]) -> Path:
    """
    Validate the requested support-bundle output path.

    The output file itself must not be a symlink. The parent directory must
    already exist and, when caller-approved roots are provided, must resolve
    under one of those roots. This prevents symlink escape writes during tests
    and CLI use.
    """
    output = output_path.expanduser()
    if output.is_symlink():
        raise SupportBundleError("support bundle output must not be a symlink")

    parent = output.parent.resolve(strict=True)
    if output.name in {".env", ".app_key"}:
        raise SupportBundleError("support bundle output filename is not allowed")
    if output.suffix.lower() != ".zip":
        raise SupportBundleError("support bundle output must be a .zip file")

    roots = tuple(root.expanduser().resolve(strict=True) for root in allowed_output_roots)
    if roots and not any(_is_relative_to(parent, root) for root in roots):
        raise SupportBundleError("support bundle output is outside approved output roots")

    return parent / output.name


def _safe_read_text(path: Path, *, max_bytes: int) -> str:
    """Read a bounded text excerpt without following symlinked log files."""
    if path.is_symlink() or not path.is_file():
        return ""
    with path.open("rb") as fh:
        return fh.read(max_bytes).decode("utf-8", errors="replace")


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    """Write JSON data with stable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    """Write UTF-8 text, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _config_summary(repo_root: Path) -> dict[str, object]:
    """Build a redacted summary of local config presence without raw values."""
    env_path = repo_root / ".env"
    app_key_path = repo_root / ".app_key"
    env_keys: list[str] = []
    redacted_env_preview: list[str] = []

    if env_path.exists() and not env_path.is_symlink() and env_path.is_file():
        for line in _safe_read_text(env_path, max_bytes=32 * 1024).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key = stripped.split("=", 1)[0].strip()
            env_keys.append(key)
            redacted_env_preview.append(f"{key}=[REDACTED]")

    return {
        "env_present": env_path.exists(),
        "env_keys": sorted(set(env_keys)),
        "redacted_env_preview": redacted_env_preview[:100],
        "app_key_present": app_key_path.exists(),
        "app_key_value": "[REDACTED]" if app_key_path.exists() else None,
        "raw_env_included": False,
        "raw_app_key_included": False,
    }


class SupportBundleBuilder:
    """Create redacted Odysseus support bundles using a fixed allowlist."""

    def create_bundle(self, options: SupportBundleOptions) -> Path:
        """
        Create a support bundle zip archive.

        Args:
            options: Output path, repository root, and bundle limits.

        Returns:
            Path to the created zip file.

        Raises:
            SupportBundleError: If the requested output path is unsafe.
        """
        repo_root = options.repo_root.resolve(strict=True)
        output = _validate_output_path(
            options.output_path,
            allowed_output_roots=options.allowed_output_roots,
        )

        with tempfile.TemporaryDirectory(prefix="odysseus-support-") as tmp:
            staging = Path(tmp)
            diagnostics = collect_diagnostics(repo_root=repo_root)
            _write_text(staging / "diagnostics.json", diagnostics_to_json(diagnostics))
            _write_json(staging / "config" / "redacted-config-summary.json", _config_summary(repo_root))
            _write_json(
                staging / "audit" / "audit-summary.json",
                diagnostics.get("audit", {}) if isinstance(diagnostics.get("audit"), dict) else {},
            )
            _write_json(
                staging / "tool-policy" / "registry-summary.json",
                diagnostics.get("tool_policy", {}) if isinstance(diagnostics.get("tool_policy"), dict) else {},
            )
            _write_json(
                staging / "runner" / "sandbox-runner-status.json",
                diagnostics.get("sandbox_runner", {}) if isinstance(diagnostics.get("sandbox_runner"), dict) else {},
            )

            if options.include_logs:
                self._write_redacted_logs(repo_root, staging, max_log_bytes=options.max_log_bytes)

            output.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for source in sorted(staging.rglob("*")):
                    if source.is_symlink() or not source.is_file():
                        continue
                    archive.write(source, source.relative_to(staging).as_posix())

        return output

    def _write_redacted_logs(self, repo_root: Path, staging: Path, *, max_log_bytes: int) -> None:
        """Copy only redacted bounded log excerpts into staging."""
        logs_dir = repo_root / "logs"
        if not logs_dir.exists() or logs_dir.is_symlink() or not logs_dir.is_dir():
            return
        for log_file in sorted(logs_dir.glob("*.log"))[:20]:
            if log_file.is_symlink() or not log_file.is_file():
                continue
            raw = _safe_read_text(log_file, max_bytes=max_log_bytes)
            redacted = redact_diagnostics_text(raw)
            _write_text(staging / "logs" / log_file.name, redacted)


def create_support_bundle(
    output_path: Path,
    *,
    repo_root: Path | None = None,
    allowed_output_roots: tuple[Path, ...] = (),
) -> Path:
    """Convenience wrapper for creating a redacted support bundle."""
    builder = SupportBundleBuilder()
    return builder.create_bundle(
        SupportBundleOptions(
            output_path=output_path,
            repo_root=repo_root or Path.cwd(),
            allowed_output_roots=allowed_output_roots,
        )
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for scripts/odysseus-support-bundle."""
    parser = argparse.ArgumentParser(description="Create a redacted Odysseus support bundle.")
    parser.add_argument("--output", required=True, help="Output zip path, for example /tmp/odysseus-support.zip")
    parser.add_argument("--repo-root", default=str(Path.cwd()), help="Odysseus repository root")
    args = parser.parse_args(argv)

    output = Path(args.output)
    repo_root = Path(args.repo_root)
    default_roots = (Path.cwd(), Path(tempfile.gettempdir()))
    created = create_support_bundle(output, repo_root=repo_root, allowed_output_roots=default_roots)
    print(f"wrote {created}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI tests.
    raise SystemExit(main())
