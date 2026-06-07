"""Security tests for action-bound confirmation tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services.review_packets import ConfirmationTokenStore, ReviewPacketError


def _issue_token(store: ConfirmationTokenStore):
    """Issue a standard token for confirmation tests."""
    return store.issue(
        user_id="alice",
        session_id="session-1",
        tool_name="shell.run",
        decision_id="decision-1",
        content="echo reviewed",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_confirmation_token_can_be_consumed_once():
    # Prevents replaying a prior approval to execute a staged action again.
    store = ConfirmationTokenStore(ttl_seconds=60)
    token = _issue_token(store)

    consumed = store.consume(
        token.token_id,
        user_id="alice",
        session_id="session-1",
        tool_name="shell.run",
        decision_id="decision-1",
        content="echo reviewed",
        now=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
    )

    assert consumed.used is True
    with pytest.raises(ReviewPacketError):
        store.consume(
            token.token_id,
            user_id="alice",
            session_id="session-1",
            tool_name="shell.run",
            decision_id="decision-1",
            content="echo reviewed",
            now=datetime(2026, 1, 1, 0, 0, 31, tzinfo=timezone.utc),
        )


def test_confirmation_token_cannot_approve_different_content():
    # Approval is bound to a content hash so edited scripts or commands require a
    # new review and confirmation.
    store = ConfirmationTokenStore(ttl_seconds=60)
    token = _issue_token(store)

    with pytest.raises(ReviewPacketError):
        store.consume(
            token.token_id,
            user_id="alice",
            session_id="session-1",
            tool_name="shell.run",
            decision_id="decision-1",
            content="echo changed",
            now=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        )


def test_confirmation_token_cannot_approve_different_user_session_or_tool():
    # Tokens must not transfer between users, sessions, or tools.
    store = ConfirmationTokenStore(ttl_seconds=60)
    token = _issue_token(store)

    mismatches = [
        {"user_id": "bob", "session_id": "session-1", "tool_name": "shell.run", "decision_id": "decision-1"},
        {"user_id": "alice", "session_id": "session-2", "tool_name": "shell.run", "decision_id": "decision-1"},
        {"user_id": "alice", "session_id": "session-1", "tool_name": "python.run", "decision_id": "decision-1"},
        {"user_id": "alice", "session_id": "session-1", "tool_name": "shell.run", "decision_id": "decision-2"},
    ]

    for mismatch in mismatches:
        with pytest.raises(ReviewPacketError):
            store.consume(
                token.token_id,
                **mismatch,
                content="echo reviewed",
                now=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )


def test_confirmation_token_expires():
    # Time limits reduce the risk of stale approvals being used long after the
    # reviewer saw the staged content.
    store = ConfirmationTokenStore(ttl_seconds=60)
    token = _issue_token(store)

    with pytest.raises(ReviewPacketError):
        store.consume(
            token.token_id,
            user_id="alice",
            session_id="session-1",
            tool_name="shell.run",
            decision_id="decision-1",
            content="echo reviewed",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=61),
        )


def test_confirmation_token_unknown_token_denies():
    # Missing tokens fail closed instead of acting as optional advisory metadata.
    store = ConfirmationTokenStore(ttl_seconds=60)

    with pytest.raises(ReviewPacketError):
        store.consume(
            "missing",
            user_id="alice",
            session_id="session-1",
            tool_name="shell.run",
            decision_id="decision-1",
            content="echo reviewed",
        )
