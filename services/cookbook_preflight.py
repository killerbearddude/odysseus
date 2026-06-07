"""
Read-only Cookbook/model-serving preflight helpers for Odysseus.

The preflight service reports host facts, warnings, and errors before an
operator attempts model installation, model download, or model-serving actions.
It intentionally does not install packages, download models, start servers,
write configuration, or mutate system state.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

try:
    from core.offline_mode import is_offline_mode
except Exception:  # pragma: no cover - defensive fallback for partial checkouts.
    def is_offline_mode() -> bool:
        """Return false when the offline helper is unavailable."""
        return os.getenv("ODYSSEUS_OFFLINE_MODE", "false").lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CookbookPreflightOptions:
    """Inputs that shape a read-only Cookbook/model-serving preflight check."""

    backend: str = "local"
    model_cache_path: Path = Path("data/model-cache")
    model_download_requested: bool = False
    hf_token_required: bool = False
    require_tmux: bool = False
    require_docker: bool = False


@dataclass(frozen=True)
class PreflightResult:
    """Structured result returned by the Cookbook preflight service."""

    ok: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)
    recommended_next_action: str = "No action required."


def _command_available(name: str) -> bool:
    """Return whether an executable is available on PATH."""
    return shutil.which(name) is not None


def _detect_wsl() -> bool:
    """Detect WSL without executing privileged commands."""
    release = platform.release().lower()
    if "microsoft" in release or "wsl" in release:
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(errors="ignore").lower()
    except OSError:
        return False


def _read_mem_total_bytes() -> int | None:
    """Read host RAM from /proc/meminfo when available."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                return int(parts[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _disk_free_bytes(path: Path) -> int | None:
    """Return free bytes for the nearest existing parent of a path."""
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return None
    return int(usage.free)


def _path_writable_without_mutation(path: Path) -> bool:
    """Check whether a path appears writable without creating files or dirs."""
    if path.exists():
        return path.is_dir() and os.access(path, os.W_OK | os.X_OK)
    parent = path.parent
    while not parent.exists() and parent.parent != parent:
        parent = parent.parent
    return parent.exists() and os.access(parent, os.W_OK | os.X_OK)


def _detect_gpu_facts() -> dict[str, object]:
    """Collect non-invasive GPU availability facts."""
    facts: dict[str, object] = {
        "gpu_vendor": "none_detected",
        "cuda_available": False,
        "rocm_available": False,
        "metal_available": sys.platform == "darwin",
        "vram_bytes": None,
    }

    if _command_available("nvidia-smi"):
        facts["gpu_vendor"] = "nvidia"
        facts["cuda_available"] = True
        try:
            proc = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
            first = proc.stdout.strip().splitlines()[0]
            facts["vram_bytes"] = int(first.strip()) * 1024 * 1024
        except Exception:
            facts["vram_bytes"] = None
    elif _command_available("rocm-smi") or _command_available("rocminfo"):
        facts["gpu_vendor"] = "amd"
        facts["rocm_available"] = True
    elif sys.platform == "darwin":
        facts["gpu_vendor"] = "apple"

    return facts


def run_cookbook_preflight(
    options: CookbookPreflightOptions | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> PreflightResult:
    """
    Run a read-only preflight check for Cookbook/model-serving operations.

    Args:
        options: Backend and cache settings for the check.
        env: Optional environment mapping used by tests and callers.

    Returns:
        A structured result containing facts, warnings, errors, and a next step.
    """
    options = options or CookbookPreflightOptions()
    env = env or os.environ
    warnings: list[str] = []
    errors: list[str] = []

    offline = is_offline_mode()
    cache_path = Path(options.model_cache_path)
    facts: dict[str, object] = {
        "os": platform.system() or "unknown",
        "platform": platform.platform(),
        "architecture": platform.machine() or "unknown",
        "python_version": platform.python_version(),
        "pip_available": _command_available("pip") or _command_available("pip3"),
        "shell_available": _command_available("bash") or _command_available("sh"),
        "tmux_available": _command_available("tmux"),
        "docker_available": _command_available("docker"),
        "wsl_detected": _detect_wsl(),
        "ram_bytes": _read_mem_total_bytes(),
        "available_disk_bytes": _disk_free_bytes(cache_path),
        "model_cache_path": str(cache_path),
        "model_cache_writable": _path_writable_without_mutation(cache_path),
        "network_available": not offline,
        "offline_mode": offline,
        "hf_token_present": bool(env.get("HF_TOKEN") or env.get("HUGGINGFACE_TOKEN")),
        "backend": options.backend,
    }
    facts.update(_detect_gpu_facts())

    if not facts["pip_available"]:
        warnings.append("pip is not available; Python package based setup cannot proceed.")
    if not facts["shell_available"]:
        errors.append("No supported shell was found on PATH.")
    if options.require_tmux and not facts["tmux_available"]:
        warnings.append("tmux is missing; tmux-backed model serving will not be available.")
    if options.require_docker and not facts["docker_available"]:
        errors.append("Docker is missing but this backend requires Docker.")
    if not facts["model_cache_writable"]:
        errors.append(f"Model cache path is not writable: {cache_path}")
    if options.model_download_requested and offline:
        errors.append("Model downloads are disabled while ODYSSEUS_OFFLINE_MODE=true.")
    if options.hf_token_required and not facts["hf_token_present"]:
        errors.append("A Hugging Face token is required for this model but was not configured.")

    recommended = _recommend_next_action(errors, warnings, facts, options)
    return PreflightResult(
        ok=not errors,
        warnings=warnings,
        errors=errors,
        facts=facts,
        recommended_next_action=recommended,
    )


def _recommend_next_action(
    errors: list[str], warnings: list[str], facts: Mapping[str, object], options: CookbookPreflightOptions
) -> str:
    """Return an actionable next step for common preflight outcomes."""
    if errors:
        if any("OFFLINE_MODE" in item for item in errors):
            return "Disable offline mode only if you intentionally want external model downloads."
        if any("Docker" in item for item in errors):
            return "Install Docker or choose a non-Docker backend."
        if any("cache" in item.lower() for item in errors):
            return "Choose a writable model cache path under approved local storage."
        return "Resolve the listed preflight errors before starting model setup."
    if warnings:
        return "Review warnings, then continue only with a backend that matches this host."
    if options.model_download_requested:
        return "Proceed to staged review for the model download action."
    return "Preflight passed; proceed to policy-gated review before starting model-serving actions."


@dataclass(frozen=True)
class HardwareProfile:
    """Hardware facts used to rank local model/backend recommendations."""

    ram_bytes: int
    vram_bytes: int | None = None
    gpu_vendor: str = "none_detected"
    wsl_detected: bool = False
    offline_mode: bool = False


@dataclass(frozen=True)
class ModelRecommendation:
    """One conservative model/backend recommendation."""

    name: str
    backend: str
    reason: str
    remote_download_required: bool = False
    gpu_required: bool = False


def recommend_models(profile: HardwareProfile) -> list[ModelRecommendation]:
    """
    Recommend conservative local model options for a hardware profile.

    The ranking is intentionally simple and safe: it avoids GPU-only backends on
    CPU-only hosts and avoids remote-download-only recommendations in offline
    mode.
    """
    recommendations: list[ModelRecommendation] = []
    vram = profile.vram_bytes or 0
    has_gpu = profile.gpu_vendor not in {"", "none", "none_detected"} and vram > 0

    if not has_gpu:
        recommendations.append(
            ModelRecommendation(
                name="small-quantized-local-model",
                backend="llama.cpp",
                reason="CPU-only host detected; prefer a small quantized model.",
                remote_download_required=False,
                gpu_required=False,
            )
        )
    elif vram < 10 * 1024**3:
        recommendations.append(
            ModelRecommendation(
                name="7b-or-smaller-quantized-model",
                backend="llama.cpp",
                reason="Limited VRAM detected; prefer smaller quantized models.",
                remote_download_required=False,
                gpu_required=True,
            )
        )
    else:
        recommendations.append(
            ModelRecommendation(
                name="larger-local-gpu-model",
                backend="vLLM",
                reason="Higher VRAM detected; larger local models may be feasible.",
                remote_download_required=False,
                gpu_required=True,
            )
        )

    if profile.wsl_detected:
        recommendations.append(
            ModelRecommendation(
                name="wsl-local-endpoint-check",
                backend="Ollama",
                reason="WSL detected; verify host/guest networking and GPU passthrough before serving.",
                remote_download_required=False,
                gpu_required=False,
            )
        )

    if not profile.offline_mode:
        recommendations.append(
            ModelRecommendation(
                name="optional-remote-download-candidate",
                backend="Hugging Face",
                reason="Network is available; staged model download may be considered after review.",
                remote_download_required=True,
                gpu_required=False,
            )
        )

    return recommendations
