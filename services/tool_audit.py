"""
SQLite-backed audit storage for Odysseus tool and path-safety decisions.

The store records policy decisions and path denials as structured, redacted
metadata. It is intentionally independent from route handlers and execution
runners so future policy, path-safety, staging, and sandbox code can audit events
without invoking tools or importing web-layer modules.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from core.audit_redaction import build_redacted_summary, hash_content, summary_to_json


AuditEventType = Literal[
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
]


VALID_AUDIT_EVENTS: frozenset[str] = frozenset(
    {
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
)

DEFAULT_AUDIT_DB = Path("data/tool_audit.sqlite")
DEFAULT_POLICY_VERSION = "tool-policy-v1"


def _utc_now() -> str:
    """
    Return an ISO-8601 UTC timestamp for audit ordering.

    Returns:
        Timezone-aware timestamp string using second and subsecond precision.
    """
    return datetime.now(timezone.utc).isoformat()


def _json_list(values: tuple[str, ...] | list[str] | None) -> str:
    """
    Serialize path lists for SQLite storage.

    Args:
        values: Path or identifier values that have already been chosen for
            persistence by the caller.

    Returns:
        Deterministic JSON array text.
    """
    return json.dumps(list(values or ()), sort_keys=True, separators=(",", ":"))


def _load_json_list(value: str | None) -> tuple[str, ...]:
    """
    Deserialize a stored JSON path list.

    Args:
        value: JSON array text from SQLite.

    Returns:
        Tuple of string values. Invalid or absent data returns an empty tuple so
        audit reads remain robust if a row is partially corrupt.
    """
    if not value:
        return ()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(item) for item in parsed)


def _default_app_commit() -> str:
    """
    Return the commit identifier supplied by deployment/CI, if available.

    Returns:
        Commit string from common environment variables, or ``unknown``. The
        store avoids invoking Git so audit writes stay fast and side-effect-free.
    """
    return (
        os.environ.get("ODYSSEUS_COMMIT")
        or os.environ.get("GITHUB_SHA")
        or os.environ.get("COMMIT_SHA")
        or "unknown"
    )


@dataclass(frozen=True)
class ToolAuditEvent:
    """
    Immutable audit record for one tool or path-security event.

    The dataclass mirrors the SQLite schema. Path lists and summaries should be
    redacted before construction because audit records are durable security
    artifacts and may be reviewed later by admins or support tooling.
    """

    event_type: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_utc_now)
    user_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    decision_id: str | None = None
    tool_name: str | None = None
    risk: str | None = None
    decision: str | None = None
    reason: str | None = None
    confirmation_id: str | None = None
    sandbox_required: bool = False
    sandbox_used: bool = False
    network_requested: bool = False
    network_allowed: bool = False
    paths_requested: tuple[str, ...] = field(default_factory=tuple)
    paths_allowed: tuple[str, ...] = field(default_factory=tuple)
    paths_denied: tuple[str, ...] = field(default_factory=tuple)
    redacted_summary: dict[str, object] = field(default_factory=dict)
    exit_code: int | None = None
    duration_ms: int | None = None
    policy_version: str = DEFAULT_POLICY_VERSION
    app_commit: str = field(default_factory=_default_app_commit)

    def __post_init__(self) -> None:
        """
        Validate stable audit invariants after dataclass initialization.

        Raises:
            ValueError: If the event type is not one of the supported audit
                events. This prevents typo-created event streams.
        """
        if self.event_type not in VALID_AUDIT_EVENTS:
            raise ValueError(f"unknown audit event type: {self.event_type}")

    def to_public_dict(self) -> dict[str, object]:
        """
        Return a JSON-compatible dictionary for tests and future admin views.

        Returns:
            Event data without exposing any raw content beyond the already
            redacted summary and caller-approved path metadata.
        """
        return asdict(self)


class ToolAuditStore:
    """
    Minimal SQLite store for redacted tool audit events.

    The store opens short-lived SQLite connections for each operation so callers
    do not need to manage connection lifetime in tests, policy services, or
    future route hooks. The database path defaults to ``data/tool_audit.sqlite``.
    """

    def __init__(self, db_path: str | Path = DEFAULT_AUDIT_DB) -> None:
        """
        Initialize the audit store and ensure the schema exists.

        Args:
            db_path: SQLite database file path. Tests should pass a temporary
                path to avoid touching persistent local audit state.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        """
        Open a SQLite connection with row dictionaries enabled.

        Returns:
            SQLite connection for a single store operation.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        """
        Create the audit table when the store is first used.

        The schema is intentionally append-only for this PR. Migration/versioning
        can be added later when admin audit export and retention policies exist.
        """
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    request_id TEXT,
                    decision_id TEXT,
                    tool_name TEXT,
                    risk TEXT,
                    decision TEXT,
                    reason TEXT,
                    confirmation_id TEXT,
                    sandbox_required INTEGER NOT NULL,
                    sandbox_used INTEGER NOT NULL,
                    network_requested INTEGER NOT NULL,
                    network_allowed INTEGER NOT NULL,
                    paths_requested TEXT NOT NULL,
                    paths_allowed TEXT NOT NULL,
                    paths_denied TEXT NOT NULL,
                    redacted_summary TEXT NOT NULL,
                    exit_code INTEGER,
                    duration_ms INTEGER,
                    policy_version TEXT NOT NULL,
                    app_commit TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_audit_events_timestamp
                ON tool_audit_events(timestamp)
                """
            )

    def record_event(self, event: ToolAuditEvent) -> ToolAuditEvent:
        """
        Persist one already-redacted audit event.

        Args:
            event: Event to store.

        Returns:
            The same event for convenient call chaining in tests and services.
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_audit_events (
                    event_id, timestamp, event_type, user_id, session_id,
                    request_id, decision_id, tool_name, risk, decision, reason,
                    confirmation_id, sandbox_required, sandbox_used,
                    network_requested, network_allowed, paths_requested,
                    paths_allowed, paths_denied, redacted_summary, exit_code,
                    duration_ms, policy_version, app_commit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.event_type,
                    event.user_id,
                    event.session_id,
                    event.request_id,
                    event.decision_id,
                    event.tool_name,
                    event.risk,
                    event.decision,
                    event.reason,
                    event.confirmation_id,
                    int(event.sandbox_required),
                    int(event.sandbox_used),
                    int(event.network_requested),
                    int(event.network_allowed),
                    _json_list(event.paths_requested),
                    _json_list(event.paths_allowed),
                    _json_list(event.paths_denied),
                    summary_to_json(event.redacted_summary),
                    event.exit_code,
                    event.duration_ms,
                    event.policy_version,
                    event.app_commit,
                ),
            )
        return event

    def recent_events(self, *, limit: int = 50) -> list[ToolAuditEvent]:
        """
        Return most recent audit events in reverse chronological order.

        Args:
            limit: Maximum number of events to return. Values below one return
                an empty list to avoid accidental unbounded queries.

        Returns:
            List of ``ToolAuditEvent`` instances.
        """
        if limit < 1:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM tool_audit_events
                ORDER BY timestamp DESC, event_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def _event_from_row(self, row: sqlite3.Row) -> ToolAuditEvent:
        """
        Convert a SQLite row back into a ``ToolAuditEvent``.

        Args:
            row: Row returned by SQLite.

        Returns:
            Reconstructed audit event.
        """
        try:
            redacted_summary = json.loads(row["redacted_summary"] or "{}")
        except json.JSONDecodeError:
            redacted_summary = {}
        return ToolAuditEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            user_id=row["user_id"],
            session_id=row["session_id"],
            request_id=row["request_id"],
            decision_id=row["decision_id"],
            tool_name=row["tool_name"],
            risk=row["risk"],
            decision=row["decision"],
            reason=row["reason"],
            confirmation_id=row["confirmation_id"],
            sandbox_required=bool(row["sandbox_required"]),
            sandbox_used=bool(row["sandbox_used"]),
            network_requested=bool(row["network_requested"]),
            network_allowed=bool(row["network_allowed"]),
            paths_requested=_load_json_list(row["paths_requested"]),
            paths_allowed=_load_json_list(row["paths_allowed"]),
            paths_denied=_load_json_list(row["paths_denied"]),
            redacted_summary=redacted_summary,
            exit_code=row["exit_code"],
            duration_ms=row["duration_ms"],
            policy_version=row["policy_version"],
            app_commit=row["app_commit"],
        )


def record_tool_requested(
    store: ToolAuditStore,
    *,
    user_id: str | None,
    session_id: str | None,
    request_id: str | None = None,
    decision_id: str | None = None,
    tool_name: str,
    risk: str,
    reason: str = "tool requested",
    content: str | bytes | None = None,
) -> ToolAuditEvent:
    """
    Record that a tool invocation was requested before policy finalization.

    Args:
        store: Audit store to write to.
        user_id: Authenticated user identifier, if available.
        session_id: Session identifier, if available.
        request_id: Request correlation identifier.
        decision_id: Policy decision identifier.
        tool_name: Registered tool name.
        risk: Declared tool risk.
        reason: Human-readable reason.
        content: Optional sensitive request details to summarize.

    Returns:
        Persisted audit event.
    """
    return store.record_event(
        ToolAuditEvent(
            event_type="tool_requested",
            user_id=user_id,
            session_id=session_id,
            request_id=request_id,
            decision_id=decision_id,
            tool_name=tool_name,
            risk=risk,
            decision="requested",
            reason=reason,
            redacted_summary=build_redacted_summary(content, content_kind="tool_request"),
        )
    )


def record_tool_allowed(
    store: ToolAuditStore,
    *,
    user_id: str | None,
    session_id: str | None,
    decision_id: str,
    tool_name: str,
    risk: str,
    reason: str,
    sandbox_required: bool = False,
    sandbox_used: bool = False,
    network_requested: bool = False,
    network_allowed: bool = False,
    content: str | bytes | None = None,
) -> ToolAuditEvent:
    """
    Record an allowed tool policy decision.

    Args mirror ``ToolAuditEvent`` fields and keep raw content optional so the
    function can be called by policy services without storing tool output.
    """
    return store.record_event(
        ToolAuditEvent(
            event_type="tool_allowed",
            user_id=user_id,
            session_id=session_id,
            decision_id=decision_id,
            tool_name=tool_name,
            risk=risk,
            decision="allow",
            reason=reason,
            sandbox_required=sandbox_required,
            sandbox_used=sandbox_used,
            network_requested=network_requested,
            network_allowed=network_allowed,
            redacted_summary=build_redacted_summary(content, content_kind="tool_decision"),
        )
    )


def record_tool_denied(
    store: ToolAuditStore,
    *,
    user_id: str | None,
    session_id: str | None,
    decision_id: str,
    tool_name: str,
    risk: str | None,
    reason: str,
    network_requested: bool = False,
    paths_requested: tuple[str, ...] | list[str] | None = None,
    content: str | bytes | None = None,
) -> ToolAuditEvent:
    """
    Record a denied tool policy decision.

    Denials are security-relevant even when no tool executes, so this helper is
    the primary hook for future policy-service integration.
    """
    return store.record_event(
        ToolAuditEvent(
            event_type="tool_denied",
            user_id=user_id,
            session_id=session_id,
            decision_id=decision_id,
            tool_name=tool_name,
            risk=risk,
            decision="deny",
            reason=reason,
            network_requested=network_requested,
            paths_requested=tuple(paths_requested or ()),
            redacted_summary=build_redacted_summary(content, content_kind="tool_denial"),
        )
    )


def record_tool_staged(
    store: ToolAuditStore,
    *,
    user_id: str | None,
    session_id: str | None,
    decision_id: str,
    tool_name: str,
    risk: str,
    reason: str,
    confirmation_id: str | None = None,
    content: str | bytes | None = None,
) -> ToolAuditEvent:
    """
    Record that a tool action was staged or requires human review.

    The event intentionally stores a redacted summary, not the staged artifact.
    Review packet storage will be introduced in a later PR.
    """
    return store.record_event(
        ToolAuditEvent(
            event_type="tool_staged",
            user_id=user_id,
            session_id=session_id,
            decision_id=decision_id,
            tool_name=tool_name,
            risk=risk,
            decision="stage",
            reason=reason,
            confirmation_id=confirmation_id,
            redacted_summary=build_redacted_summary(content, content_kind="tool_stage"),
        )
    )


def record_path_denied(
    store: ToolAuditStore,
    *,
    user_id: str | None,
    session_id: str | None,
    request_id: str | None = None,
    decision_id: str | None = None,
    tool_name: str | None = None,
    reason: str,
    path: str,
    content: str | bytes | None = None,
) -> ToolAuditEvent:
    """
    Record a path-safety denial without storing file contents.

    Args:
        store: Audit store to write to.
        user_id: User associated with the path request.
        session_id: Session associated with the path request.
        request_id: Request correlation identifier.
        decision_id: Optional policy decision identifier.
        tool_name: Optional tool involved in the path request.
        reason: User-visible denial reason that must not include secrets.
        path: Denied path metadata. Callers should avoid including file content.
        content: Optional raw text associated with the request. It is summarized
            and redacted, never stored directly.

    Returns:
        Persisted path-denial event.
    """
    return store.record_event(
        ToolAuditEvent(
            event_type="path_denied",
            user_id=user_id,
            session_id=session_id,
            request_id=request_id,
            decision_id=decision_id,
            tool_name=tool_name,
            decision="deny",
            reason=reason,
            paths_requested=(path,),
            paths_denied=(path,),
            # Path denials often involve private documents or host files. Store
            # only path metadata and content-derived counts/hashes; never store a
            # raw excerpt from denied file content.
            redacted_summary=build_redacted_summary(
                "[path content redacted]",
                content_kind="path_denial",
                metadata={
                    "denied_path": path,
                    "content_hash": hash_content(content),
                    "content_byte_count": len(
                        content if isinstance(content, bytes) else str(content or "").encode("utf-8")
                    ),
                    "content_line_count": (
                        content.decode("utf-8", errors="replace").count("\n") + 1
                        if isinstance(content, bytes) and content
                        else str(content or "").count("\n") + (1 if content else 0)
                    ),
                    "raw_content_logged": False,
                },
            ),
        )
    )
