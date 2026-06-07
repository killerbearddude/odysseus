#!/usr/bin/env python3
"""
Generate the Odysseus release manifest.

The manifest records build metadata and the minimum release checks expected
before publishing an artifact. The generated RELEASE_MANIFEST.json is ignored so
CI can create it before distcheck without making the Git tree dirty.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "RELEASE_MANIFEST.json"


def _git(args: Sequence[str], *, default: str = "") -> str:
    """
    Run a Git command from the repository root.

    Args:
        args: Git arguments after the ``git`` executable.
        default: Fallback value when Git is unavailable or the command fails.

    Returns:
        Stripped stdout from the Git command, or ``default`` on failure.
    """
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return default

    return result.stdout.strip()


def _is_dirty() -> bool:
    """
    Return True when Git reports tracked or untracked non-ignored changes.

    This mirrors the release hygiene expectation that release metadata should be
    generated from a clean, reproducible tree.
    """
    return bool(_git(["status", "--porcelain"], default="dirty"))


def build_manifest() -> dict[str, object]:
    """
    Build the release manifest payload.

    Returns:
        JSON-serializable manifest metadata.
    """
    return {
        "name": "odysseus",
        "version": "0.0.0-alpha",
        "commit": _git(["rev-parse", "HEAD"], default="unknown"),
        "branch": _git(["branch", "--show-current"], default="unknown"),
        "dirty": _is_dirty(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "required_checks": [
            "compileall",
            "node --check",
            "pytest",
            "docker smoke",
            "distcheck",
        ],
        "excluded_paths": [
            ".env",
            ".app_key",
            "data/",
            "logs/",
            "uploads/",
            "generated/",
            "backups/",
            "__pycache__/",
        ],
    }


def main() -> int:
    """
    Write RELEASE_MANIFEST.json.

    Returns:
        Process exit code.
    """
    manifest = build_manifest()
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
