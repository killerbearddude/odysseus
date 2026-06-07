"""
Negative security tests for malicious text attempting to escalate tool authority.

These tests model the boundary where untrusted content may influence a proposed
tool call, but only application-owned policy, staging, confirmation, path safety,
and audit services can authorize anything. No real tool execution occurs here.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from services.review_packets import ReviewPacketService
from services.staging_store import StagingStore
from services.tool_audit import ToolAuditStore, record_tool_denied
from services.tool_policy_service import ToolPolicyRequest, ToolPolicyService


FIXTURE_DIR = Path("tests/fixtures/prompt_injection")


class ExecutionSpy:
    """Test double that records whether an execution boundary was crossed."""

    def __init__(self) -> None:
        """Initialize the spy with no calls recorded."""
        self.called = False

    def __call__(self, *_args: object, **_kwargs: object) -> None:
        """Record an attempted execution without executing anything."""
        self.called = True


def _fixture(name: str) -> str:
    """
    Load an inert prompt-injection fixture.

    Args:
        name: Fixture filename under ``tests/fixtures/prompt_injection``.

    Returns:
        Fixture text.
    """
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _raw_database_text(db_path: Path) -> str:
    """
    Return serialized audit rows for raw-leak assertions.

    Args:
        db_path: Tool audit SQLite path.

    Returns:
        JSON representation of persisted audit rows.
    """
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT event_type, tool_name, reason, redacted_summary FROM tool_audit_events"
        ).fetchall()
    return json.dumps(rows, sort_keys=True)


def test_malicious_note_cannot_trigger_shell_execution():
    # Prevents retrieved note text from becoming authority to run critical shell
    # tools. The proposed tool is denied and the execution spy is never called.
    malicious_text = _fixture("malicious-note.md")
    executor = ExecutionSpy()
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="alice",
            session_id="session-1",
            tool_name="shell.run",
            admin_status=False,
            sandbox_available=True,
            requested_paths=("~/.ssh/id_rsa",),
        )
    )

    if decision.decision == "allow":
        executor(malicious_text)

    assert decision.decision == "deny"
    assert "admin" in decision.reason
    assert executor.called is False


def test_malicious_transcript_cannot_trigger_python_execution():
    # Prevents transcript text from granting Python execution. Critical Python
    # tools still require admin, sandbox, review, and confirmation.
    malicious_text = _fixture("malicious-transcript.txt")
    executor = ExecutionSpy()
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="alice",
            session_id="session-1",
            tool_name="python.run",
            admin_status=True,
            sandbox_available=True,
            requested_paths=(".env",),
        )
    )

    if decision.decision == "allow":
        executor(malicious_text)

    assert decision.decision == "review_required"
    assert "confirmation" in decision.reason
    assert executor.called is False


def test_malicious_clipboard_cannot_mark_generated_script_as_reviewed(tmp_path: Path):
    # Clipboard text may claim approval, but generated artifacts must remain
    # unreviewed drafts until a server-side confirmation flow approves them.
    malicious_text = _fixture("malicious-clipboard.txt")
    service = ReviewPacketService(StagingStore(tmp_path / "staging"))

    artifact, packet = service.stage_generated_script(
        malicious_text,
        requested_goal="Review clipboard-proposed maintenance action",
        tool_name="shell.run",
        risk_level="Critical",
        why_risky="Clipboard content is untrusted and requests shell execution.",
        files_touched=(".app_key",),
        network_access="requested by untrusted text",
    )

    script_text = artifact.path.read_text(encoding="utf-8")
    assert "# Reviewed by user: no" in script_text
    assert "## Human Decision" in packet.markdown
    assert "pending" in packet.markdown


def test_tool_denial_is_auditable_without_storing_raw_secret(tmp_path: Path):
    # Denials should be observable, but provider keys embedded in malicious text
    # must be redacted before the event is persisted.
    malicious_text = _fixture("malicious-note.md")
    store = ToolAuditStore(tmp_path / "tool_audit.sqlite")

    event = record_tool_denied(
        store,
        user_id="alice",
        session_id="session-1",
        decision_id="decision-1",
        tool_name="shell.run",
        risk="critical",
        reason="policy denied untrusted shell request",
        paths_requested=("~/.ssh/id_rsa", ".env"),
        content=malicious_text,
    )

    raw_db = _raw_database_text(store.db_path)
    assert event.event_type == "tool_denied"
    assert event.decision == "deny"
    assert "sk-testsecretvalue" not in raw_db
    assert "[REDACTED" in raw_db
