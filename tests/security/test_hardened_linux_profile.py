"""
Regression tests for the optional hardened Linux deployment profile.

The tests inspect documentation and example unit files only. They do not require
systemd and do not change host permissions.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "HARDENED_LINUX_DEPLOYMENT.md"
SYSTEMD_DIR = REPO_ROOT / "deploy" / "systemd"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _service(name: str) -> str:
    return _read(SYSTEMD_DIR / name)


def test_hardened_profile_document_exists_and_marks_profile_optional():
    # Regression guard: hardening profile must not be confused with default install.
    text = _read(DOC)

    assert "optional advanced Linux deployment profile" in text
    assert "not the default install path" in text
    assert "does not make Odysseus safe for unauthenticated public internet exposure" in text
    assert "Rollback instructions" in text


def test_document_covers_required_operational_topics():
    # Regression guard: operators need a full runbook, not only systemd snippets.
    text = _read(DOC)
    required = [
        "Threat model",
        "Required operator skill level",
        "Service users and groups",
        "Directory layout",
        "Ownership model",
        "Unix socket guidance",
        "Backup and restore considerations",
        "Audit log considerations",
        "Diagnostics collector isolation",
        "Model worker isolation",
        "Unsupported configurations",
        "Validation checklist",
    ]

    for topic in required:
        assert topic in text


def test_example_systemd_units_exist():
    # Regression guard: docs must be backed by concrete example files.
    expected = [
        "odysseus-web.service",
        "odysseus-runner.service",
        "odysseus-model.service",
        "odysseus-diagnostics.service",
        "tmpfiles.conf",
        "sysusers.conf",
    ]

    for name in expected:
        assert (SYSTEMD_DIR / name).exists(), name


def test_all_example_services_enable_core_systemd_hardening():
    # Regression guard: example units should not omit basic sandbox settings.
    required = [
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SystemCallArchitectures=native",
    ]

    for unit in SYSTEMD_DIR.glob("odysseus-*.service"):
        text = _read(unit)
        for setting in required:
            assert setting in text, f"{unit.name} missing {setting}"


def test_socket_examples_are_restricted_not_world_writable():
    # Regression guard: internal sockets must not be exposed to all local users.
    text = _read(SYSTEMD_DIR / "tmpfiles.conf")

    assert "/run/odysseus/runner.sock 0660 odysseus-runner odysseus-web" in text
    assert "/run/odysseus/model.sock 0660 odysseus-model odysseus-web" in text
    assert "0777" not in text
    assert "0666" not in text
