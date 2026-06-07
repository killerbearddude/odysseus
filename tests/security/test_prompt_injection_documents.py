"""
Negative tests for malicious document and webpage content.

Documents and webpages are untrusted input. They may propose tool calls or policy
changes, but they cannot mutate the application-owned tool registry or bypass
path-safety checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.path_safety import PathSafetyError, validate_read_path
from core.tool_registry import get_tool_policy
from services.tool_audit import ToolAuditStore, record_path_denied
from services.tool_policy_service import ToolPolicyRequest, ToolPolicyService


FIXTURE_DIR = Path("tests/fixtures/prompt_injection")


def _fixture(name: str) -> str:
    """Return fixture text for document-oriented prompt-injection tests."""
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("tool_name", ["shell.run", "python.run"])
def test_malicious_document_text_cannot_invoke_execution_tools(tool_name: str):
    # Prevents untrusted document text from becoming authority to invoke shell or
    # Python execution. The policy layer still owns the decision.
    _fixture("malicious-note.md")
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="reader",
            session_id="session-1",
            tool_name=tool_name,
            admin_status=False,
            sandbox_available=True,
        )
    )

    assert decision.decision == "deny"
    assert "admin" in decision.reason


def test_malicious_webpage_cannot_modify_tool_policy():
    # Prevents webpage text from weakening static application-owned policy.
    # The registry remains unchanged even when the content instructs otherwise.
    webpage = _fixture("malicious-webpage.html")
    before = get_tool_policy("shell.run")
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="reader",
            session_id="session-1",
            tool_name="shell.run",
            admin_status=False,
            sandbox_available=True,
        )
    )
    after = get_tool_policy("shell.run")

    assert "does not require admin" in webpage
    assert before == after
    assert after is not None
    assert after.admin_required is True
    assert after.confirmation_required is True
    assert after.sandbox_required is True
    assert decision.decision == "deny"


@pytest.mark.parametrize("sensitive_path", ["~/.ssh/id_rsa", ".env", ".env.local", ".app_key"])
def test_malicious_text_requesting_sensitive_paths_is_denied(tmp_path: Path, sensitive_path: str):
    # Prevents prompt-injection text from using path requests to read secrets.
    # The path-safety helper rejects known sensitive paths before any read occurs.
    approved_root = tmp_path / "data" / "imports"
    approved_root.mkdir(parents=True)

    with pytest.raises(PathSafetyError):
        validate_read_path(
            sensitive_path,
            approved_roots=(approved_root,),
            base_dir=tmp_path,
        )


def test_path_denial_from_malicious_document_is_audit_ready(tmp_path: Path):
    # Path denials should be recordable without storing raw document contents.
    malicious_text = _fixture("malicious-note.md")
    store = ToolAuditStore(tmp_path / "tool_audit.sqlite")

    event = record_path_denied(
        store,
        user_id="reader",
        session_id="session-1",
        decision_id="decision-path-1",
        tool_name="document.ingest",
        reason="path safety denied sensitive path",
        path="~/.ssh/id_rsa",
        content=malicious_text,
    )

    assert event.event_type == "path_denied"
    assert event.paths_denied == ("~/.ssh/id_rsa",)
    assert event.redacted_summary["raw_content_logged"] is False
    assert "content_hash" in event.redacted_summary["metadata"]
