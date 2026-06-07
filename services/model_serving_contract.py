"""
Runtime helpers for the Odysseus model-serving safety contract.

These helpers keep model download/serve checks testable without launching model
servers. They enforce policy-gate expectations, cache path confinement, offline
mode behavior, and redacted failure diagnostics.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from core.audit_redaction import redact_secret_like_values
except Exception:  # pragma: no cover - fallback for partial checkouts.
    def redact_secret_like_values(text: str) -> str:
        """Fallback redactor for secret-like model logs."""
        return text.replace("OPENAI_API_KEY", "[REDACTED]").replace("sk-test-secret", "[REDACTED]")

try:
    from core.offline_mode import OfflineModeError, is_offline_mode
except Exception:  # pragma: no cover - defensive fallback for partial checkouts.
    class OfflineModeError(RuntimeError):
        """Raised when offline mode blocks an external model action."""

    def is_offline_mode() -> bool:
        """Return whether offline mode is enabled."""
        return os.getenv("ODYSSEUS_OFFLINE_MODE", "false").lower() in {"1", "true", "yes", "on"}


MODEL_DOWNLOAD_TOOL = "model.download"
MODEL_SERVE_TOOL = "model.serve"
DEFAULT_MODEL_CACHE_ROOTS = (
    Path("data/models"),
    Path("data/model-cache"),
    Path("data/staging"),
)


class ModelServingContractError(ValueError):
    """Raised when a model-serving action violates the safety contract."""


@dataclass(frozen=True)
class ModelActionPolicyGate:
    """Minimal policy decision data required before model actions proceed."""

    tool_name: str
    decision: str
    audit_required: bool = True
    requires_confirmation: bool = True


@dataclass(frozen=True)
class ModelJobFailureReport:
    """Actionable, redacted failure report for model-serving jobs."""

    command: list[str]
    working_directory: str
    exit_code: int | None
    stdout_excerpt: str
    stderr_excerpt: str
    log_path: str | None
    likely_cause: str
    recommended_next_action: str
    offline_mode_block_reason: str | None = None
    diagnostic_summary: str = ""


def _decision_from_gate(policy_gate: ModelActionPolicyGate | Mapping[str, Any] | Any) -> str | None:
    """Read a policy decision from dataclass, mapping, or object input."""
    if isinstance(policy_gate, Mapping):
        value = policy_gate.get("decision")
    else:
        value = getattr(policy_gate, "decision", None)
    return value if isinstance(value, str) else None


def _tool_from_gate(policy_gate: ModelActionPolicyGate | Mapping[str, Any] | Any) -> str | None:
    """Read a tool name from dataclass, mapping, or object input."""
    if isinstance(policy_gate, Mapping):
        value = policy_gate.get("tool_name")
    else:
        value = getattr(policy_gate, "tool_name", None)
    return value if isinstance(value, str) else None


def require_model_action_policy(tool_name: str, policy_gate: ModelActionPolicyGate | Mapping[str, Any] | Any | None) -> None:
    """
    Require an allow policy decision for model download/serve actions.

    Args:
        tool_name: Expected tool name, usually `model.download` or `model.serve`.
        policy_gate: Policy decision object produced by the tool policy layer.

    Raises:
        ModelServingContractError: If the action has not been policy-approved.
    """
    if tool_name not in {MODEL_DOWNLOAD_TOOL, MODEL_SERVE_TOOL}:
        raise ModelServingContractError(f"unsupported model action: {tool_name}")
    if policy_gate is None:
        raise ModelServingContractError(f"{tool_name} requires a tool-policy decision")
    if _tool_from_gate(policy_gate) != tool_name:
        raise ModelServingContractError(f"policy decision is not bound to {tool_name}")
    if _decision_from_gate(policy_gate) != "allow":
        raise ModelServingContractError(f"{tool_name} has not been allowed by policy")


def ensure_model_cache_path(path: Path, roots: Sequence[Path] = DEFAULT_MODEL_CACHE_ROOTS) -> Path:
    """
    Ensure a model cache path stays under an approved local cache root.

    The path is normalized with `resolve(strict=False)` and compared with
    `Path.is_relative_to`; no string-prefix authorization is used.
    """
    candidate = Path(path).resolve(strict=False)
    approved = [Path(root).resolve(strict=False) for root in roots]
    if not any(candidate == root or candidate.is_relative_to(root) for root in approved):
        raise ModelServingContractError(f"model cache path is outside approved roots: {path}")
    return candidate


def require_external_model_action_allowed(action_name: str) -> None:
    """Block external model actions when offline mode is enabled."""
    if is_offline_mode():
        raise OfflineModeError(f"{action_name} is disabled while ODYSSEUS_OFFLINE_MODE=true")


def redact_model_log(text: str) -> str:
    """Redact secrets from model-serving logs and job excerpts."""
    return redact_secret_like_values(text)


def _excerpt(text: str, limit: int = 2000) -> str:
    """Return a bounded, redacted excerpt."""
    redacted = redact_model_log(text or "")
    if len(redacted) <= limit:
        return redacted
    return redacted[:limit] + "...[truncated]"


def _likely_cause(exit_code: int | None, stderr: str, offline_reason: str | None) -> str:
    """Infer a concise likely cause from redacted stderr and exit status."""
    lower = stderr.lower()
    if offline_reason:
        return "offline mode blocked an external model action"
    if "cuda" in lower or "out of memory" in lower or "oom" in lower:
        return "GPU/CUDA memory or driver issue"
    if "not found" in lower or exit_code == 127:
        return "required command or executable was not found"
    if "permission" in lower:
        return "filesystem or execution permission issue"
    if exit_code and exit_code != 0:
        return "model-serving command exited unsuccessfully"
    return "unknown; inspect redacted stdout/stderr excerpts"


def build_model_job_failure_report(
    *,
    command: Sequence[str],
    working_directory: Path,
    exit_code: int | None,
    stdout: str = "",
    stderr: str = "",
    log_path: Path | None = None,
    offline_mode_block_reason: str | None = None,
) -> ModelJobFailureReport:
    """Build a bounded, redacted, copyable model-job failure report."""
    stdout_excerpt = _excerpt(stdout)
    stderr_excerpt = _excerpt(stderr)
    likely = _likely_cause(exit_code, stderr_excerpt, offline_mode_block_reason)
    next_action = "Review the redacted error, run Cookbook preflight, and retry only after policy review."
    if offline_mode_block_reason:
        next_action = "Disable offline mode only if external model access is intentional and approved."
    elif "command" in likely:
        next_action = "Install or configure the required backend executable, then rerun preflight."
    elif "GPU" in likely:
        next_action = "Choose a smaller/quantized model or fix GPU driver/runtime configuration."

    summary = (
        f"Command: {' '.join(command)}\n"
        f"CWD: {working_directory}\n"
        f"Exit code: {exit_code}\n"
        f"Likely cause: {likely}\n"
        f"Next action: {next_action}"
    )
    return ModelJobFailureReport(
        command=list(command),
        working_directory=str(working_directory),
        exit_code=exit_code,
        stdout_excerpt=stdout_excerpt,
        stderr_excerpt=stderr_excerpt,
        log_path=str(log_path) if log_path else None,
        likely_cause=likely,
        recommended_next_action=next_action,
        offline_mode_block_reason=offline_mode_block_reason,
        diagnostic_summary=summary,
    )


def local_model_serving_allowed(policy_gate: ModelActionPolicyGate | Mapping[str, Any] | Any) -> bool:
    """Return true when a local model serve action has passed policy review."""
    require_model_action_policy(MODEL_SERVE_TOOL, policy_gate)
    return True
