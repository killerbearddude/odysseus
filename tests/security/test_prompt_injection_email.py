"""
Negative tests for malicious email content.

Email bodies are untrusted text. They cannot trigger send/delete actions, approve
themselves, or leak raw credentials into audit storage.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from services.review_packets import ConfirmationTokenStore, ReviewPacketError
from services.tool_audit import ToolAuditStore, record_tool_denied
from services.tool_policy_service import ToolPolicyRequest, ToolPolicyService


FIXTURE_DIR = Path("tests/fixtures/prompt_injection")


class EmailSenderSpy:
    """Test double that records whether email sending was attempted."""

    def __init__(self) -> None:
        """Initialize with no sent messages."""
        self.sent_messages: list[str] = []

    def send(self, body: str) -> None:
        """Record a body without sending network email."""
        self.sent_messages.append(body)


def _fixture(name: str) -> str:
    """Return a prompt-injection email fixture."""
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _raw_database_text(db_path: Path) -> str:
    """Serialize audit rows for raw-secret leak assertions."""
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT event_type, tool_name, reason, redacted_summary FROM tool_audit_events"
        ).fetchall()
    return json.dumps(rows, sort_keys=True)


def test_malicious_email_cannot_trigger_send_action():
    # Prevents an email body from directly causing another email send. The
    # high-risk send tool still requires explicit human confirmation.
    email_body = _fixture("malicious-email.eml")
    sender = EmailSenderSpy()
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="alice",
            session_id="session-email",
            tool_name="email.send",
            admin_status=True,
            network_requested=True,
        )
    )

    if decision.decision == "allow":
        sender.send(email_body)

    assert decision.decision == "review_required"
    assert sender.sent_messages == []


def test_malicious_email_cannot_approve_different_content():
    # Confirmation tokens are content-bound, so text claiming approval cannot
    # reuse a token for a different malicious email body.
    token_store = ConfirmationTokenStore(ttl_seconds=60)
    reviewed_content = "Subject: Reviewed\n\nApproved benign draft."
    malicious_email = _fixture("malicious-email.eml")
    token = token_store.issue(
        user_id="alice",
        session_id="session-email",
        tool_name="email.send",
        decision_id="decision-email-1",
        content=reviewed_content,
    )

    with pytest.raises(ReviewPacketError):
        token_store.consume(
            token.token_id,
            user_id="alice",
            session_id="session-email",
            tool_name="email.send",
            decision_id="decision-email-1",
            content=malicious_email,
        )


def test_malicious_email_cannot_approve_different_user_or_session():
    # Confirmation tokens are bound to the reviewing user and session, so email
    # text cannot transfer approval to another user/session context.
    token_store = ConfirmationTokenStore(ttl_seconds=60)
    reviewed_content = "Subject: Reviewed\n\nApproved benign draft."
    token = token_store.issue(
        user_id="alice",
        session_id="session-email",
        tool_name="email.send",
        decision_id="decision-email-2",
        content=reviewed_content,
    )

    with pytest.raises(ReviewPacketError):
        token_store.consume(
            token.token_id,
            user_id="mallory",
            session_id="session-email",
            tool_name="email.send",
            decision_id="decision-email-2",
            content=reviewed_content,
        )

    with pytest.raises(ReviewPacketError):
        token_store.consume(
            token.token_id,
            user_id="alice",
            session_id="different-session",
            tool_name="email.send",
            decision_id="decision-email-2",
            content=reviewed_content,
        )


def test_malicious_email_denial_audit_redacts_password(tmp_path: Path):
    # Denied email actions should be auditable without storing raw passwords from
    # the malicious email body.
    email_body = _fixture("malicious-email.eml")
    store = ToolAuditStore(tmp_path / "tool_audit.sqlite")

    event = record_tool_denied(
        store,
        user_id="alice",
        session_id="session-email",
        decision_id="decision-email-3",
        tool_name="email.send",
        risk="high",
        reason="policy denied unconfirmed email send",
        network_requested=True,
        content=email_body,
    )
    raw_db = _raw_database_text(store.db_path)

    assert event.event_type == "tool_denied"
    assert "hunter2" not in raw_db
    assert "[REDACTED" in raw_db
