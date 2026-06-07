"""
Security tests for SQLite-backed tool audit logging.

These tests verify that tool-policy decisions and path denials are persisted as
redacted metadata. They intentionally avoid any live tool execution so audit
behavior remains independently testable.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from services.tool_audit import (
    VALID_AUDIT_EVENTS,
    ToolAuditEvent,
    ToolAuditStore,
    record_path_denied,
    record_tool_denied,
    record_tool_staged,
)


def _store(tmp_path: Path) -> ToolAuditStore:
    """Create an isolated audit store for one test."""
    return ToolAuditStore(tmp_path / "tool_audit.sqlite")


def _raw_database_text(db_path: Path) -> str:
    """Return all audit row text so tests can assert secrets were not stored."""
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT event_type, user_id, session_id, request_id, decision_id, tool_name, risk, decision, reason, paths_requested, paths_allowed, paths_denied, redacted_summary FROM tool_audit_events"
        ).fetchall()
    return json.dumps(rows, sort_keys=True)


def test_tool_deny_event_is_persisted(tmp_path: Path):
    # Denied tools are security-relevant even though no execution happened.
    store = _store(tmp_path)

    event = record_tool_denied(
        store,
        user_id="alice",
        session_id="session-1",
        decision_id="decision-1",
        tool_name="shell.run",
        risk="critical",
        reason="admin required",
        content="command=cat /etc/passwd",
    )

    recent = store.recent_events()
    assert recent[0].event_id == event.event_id
    assert recent[0].event_type == "tool_denied"
    assert recent[0].decision == "deny"
    assert recent[0].tool_name == "shell.run"
    assert recent[0].reason == "admin required"


def test_tool_stage_decision_is_persisted(tmp_path: Path):
    # Staged decisions must be observable before later review-packet work executes them.
    store = _store(tmp_path)

    event = record_tool_staged(
        store,
        user_id="alice",
        session_id="session-1",
        decision_id="decision-2",
        tool_name="file.write",
        risk="high",
        reason="confirmation required",
        confirmation_id="confirm-1",
        content="write private draft",
    )

    stored = store.recent_events()[0]
    assert stored.event_id == event.event_id
    assert stored.event_type == "tool_staged"
    assert stored.decision == "stage"
    assert stored.confirmation_id == "confirm-1"


def test_path_denial_event_includes_metadata_without_file_content(tmp_path: Path):
    # Path denials should include useful metadata without copying private file contents.
    store = _store(tmp_path)
    private_content = "very private document body that must not enter audit storage"

    record_path_denied(
        store,
        user_id="alice",
        session_id="session-1",
        request_id="request-1",
        decision_id="decision-3",
        tool_name="document.ingest",
        reason="path outside approved roots",
        path="/home/alice/private.txt",
        content=private_content,
    )

    stored = store.recent_events()[0]
    raw_db = _raw_database_text(store.db_path)

    assert stored.event_type == "path_denied"
    assert stored.paths_denied == ("/home/alice/private.txt",)
    assert "private.txt" in raw_db
    assert private_content not in raw_db
    assert stored.redacted_summary["raw_content_logged"] is False


def test_api_keys_are_not_stored_in_audit_database(tmp_path: Path):
    # Persistent SQLite rows must not contain provider keys even in summaries.
    store = _store(tmp_path)

    record_tool_denied(
        store,
        user_id="alice",
        session_id="session-1",
        decision_id="decision-4",
        tool_name="web_research.run",
        risk="medium",
        reason="offline mode blocks network",
        content="OPENAI_API_KEY=sk-testsecretvalue1234567890",
    )

    raw_db = _raw_database_text(store.db_path)
    assert "sk-testsecretvalue" not in raw_db
    assert "REDACTED" in raw_db


def test_audit_event_ids_are_unique(tmp_path: Path):
    # Unique IDs let later review, export, and diagnostics reference exact events.
    store = _store(tmp_path)

    first = record_tool_denied(
        store,
        user_id="alice",
        session_id="s1",
        decision_id="d1",
        tool_name="shell.run",
        risk="critical",
        reason="admin required",
    )
    second = record_tool_denied(
        store,
        user_id="alice",
        session_id="s1",
        decision_id="d2",
        tool_name="python.run",
        risk="critical",
        reason="sandbox unavailable",
    )

    assert first.event_id != second.event_id
    assert len({event.event_id for event in store.recent_events(limit=10)}) == 2


def test_audit_store_can_query_recent_events(tmp_path: Path):
    # Recent-event queries are the read path future admin-only views will use.
    store = _store(tmp_path)

    for index in range(3):
        record_tool_denied(
            store,
            user_id="alice",
            session_id="s1",
            decision_id=f"decision-{index}",
            tool_name="shell.run",
            risk="critical",
            reason=f"reason-{index}",
        )

    recent = store.recent_events(limit=2)
    assert len(recent) == 2
    assert all(isinstance(event, ToolAuditEvent) for event in recent)


def test_supported_audit_event_types_cover_roadmap_events():
    # Prevents removing event names needed by later staging, sandbox, and network PRs.
    expected = {
        "tool_requested",
        "tool_allowed",
        "tool_denied",
        "tool_staged",
        "tool_confirmed",
        "tool_executed",
        "tool_failed",
        "path_allowed",
        "path_denied",
        "sandbox_started",
        "sandbox_failed",
        "network_denied",
        "review_packet_generated",
        "policy_violation",
        "offline_blocked",
    }

    assert expected <= VALID_AUDIT_EVENTS
