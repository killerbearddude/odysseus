"""
Negative-permission tests for hardened Linux deployment examples.

These tests parse example unit/config files and assert they do not grant unsafe
permissions. They are static checks and do not require root or systemd.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIR = REPO_ROOT / "deploy" / "systemd"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _unit(name: str) -> str:
    return _read(SYSTEMD_DIR / name)


def _line_values(text: str, key: str) -> list[str]:
    prefix = f"{key}="
    return [line.removeprefix(prefix).strip() for line in text.splitlines() if line.startswith(prefix)]


def test_runner_service_does_not_run_as_root_or_docker_group():
    # Regression guard: the runner is the highest-risk worker and must stay least-privileged.
    text = _unit("odysseus-runner.service")

    assert "User=odysseus-runner" in text
    assert "Group=odysseus-runner" in text
    assert "User=root" not in text
    assert "Group=docker" not in text
    assert "SupplementaryGroups=docker" not in text
    assert "docker.sock" in text
    assert "/var/run/docker.sock" in " ".join(_line_values(text, "InaccessiblePaths"))


def test_runner_write_paths_are_limited_to_workspace_and_staging():
    # Regression guard: runner must not write documents, app secrets, models, or audit logs.
    text = _unit("odysseus-runner.service")
    values = _line_values(text, "ReadWritePaths")
    assert values == ["/srv/odysseus/workspaces /srv/odysseus/staging"]

    inaccessible = " ".join(_line_values(text, "InaccessiblePaths"))
    assert "/srv/odysseus/documents" in inaccessible
    assert "/srv/odysseus/app/.env" in inaccessible
    assert "/srv/odysseus/app/.app_key" in inaccessible
    assert "/var/log/odysseus/audit.jsonl" in inaccessible


def test_web_service_uses_strict_system_protection_and_no_ambient_caps():
    # Regression guard: web/API service should not silently gain host-level privileges.
    text = _unit("odysseus-web.service")

    assert "User=odysseus-web" in text
    assert "ProtectSystem=strict" in text
    assert "NoNewPrivileges=true" in text
    assert "AmbientCapabilities=" in text
    assert "CapabilityBoundingSet=" in text
    assert "User=root" not in text


def test_diagnostics_service_is_read_only_except_diagnostics_output():
    # Regression guard: diagnostics collection must not become broad log scraping with writes.
    text = _unit("odysseus-diagnostics.service")

    assert "User=odysseus-diagnostics" in text
    assert "ReadOnlyPaths=/srv/odysseus /var/log/odysseus" in text
    assert "ReadWritePaths=/srv/odysseus/diagnostics" in text
    assert "/var/run/docker.sock" in " ".join(_line_values(text, "InaccessiblePaths"))


def test_model_service_cannot_read_documents_or_write_audit_log():
    # Regression guard: model serving should receive broker-selected context, not raw documents.
    text = _unit("odysseus-model.service")
    inaccessible = " ".join(_line_values(text, "InaccessiblePaths"))

    assert "User=odysseus-model" in text
    assert "/srv/odysseus/documents" in inaccessible
    assert "/var/log/odysseus/audit.jsonl" in inaccessible
    assert "/var/run/docker.sock" in inaccessible
    assert "ReadWritePaths=/srv/odysseus/models /srv/odysseus/cache /var/log/odysseus /run/odysseus" in text


def _systemd_values(text: str, key: str) -> list[str]:
    """Return whitespace-delimited values for a repeated systemd directive."""
    values: list[str] = []
    prefix = f"{key}="
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.startswith(prefix):
            continue
        values.extend(stripped[len(prefix):].split())
    return values


def test_no_example_service_grants_dangerous_runtime_access():
    # Regression guard: examples must not normalize unsafe privileges.
    forbidden_exact_lines = [
        "User=root",
        "Group=docker",
        "SupplementaryGroups=docker",
        "SupplementaryGroups=sudo",
        "SupplementaryGroups=adm",
        "AmbientCapabilities=CAP_",
        "CapabilityBoundingSet=CAP_",
        "BindPaths=/var/run/docker.sock",
    ]
    forbidden_readwrite_paths = {
        "/",
        "/etc",
        "/home",
        "/var/run/docker.sock",
    }

    for unit in SYSTEMD_DIR.glob("odysseus-*.service"):
        text = _read(unit)
        lines = {line.strip() for line in text.splitlines() if line.strip()}
        for line in forbidden_exact_lines:
            assert line not in lines, f"{unit.name} grants {line}"

        readwrite_paths = set(_systemd_values(text, "ReadWritePaths"))
        assert not (readwrite_paths & forbidden_readwrite_paths), (
            f"{unit.name} grants dangerous ReadWritePaths: "
            f"{sorted(readwrite_paths & forbidden_readwrite_paths)}"
        )


def test_tmpfiles_permissions_keep_audit_and_sockets_restricted():
    # Regression guard: file/socket examples must avoid world-writable modes.
    text = _read(SYSTEMD_DIR / "tmpfiles.conf")

    assert "/var/log/odysseus/audit.jsonl 0640 odysseus-web odysseus-web" in text
    assert "/run/odysseus/runner.sock 0660 odysseus-runner odysseus-web" in text
    assert "/run/odysseus/model.sock 0660 odysseus-model odysseus-web" in text
    assert " 0777 " not in text
    assert " 0666 " not in text
