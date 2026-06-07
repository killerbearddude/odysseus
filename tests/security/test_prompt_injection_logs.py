"""
Negative tests for malicious log and transcript content.

Logs are diagnostic input, not a command channel. These tests ensure malicious log
lines cannot cross execution, staging, or network boundaries without policy and
review controls.
"""

from __future__ import annotations

from pathlib import Path

from services.review_packets import ReviewPacketService
from services.staging_store import StagingStore
from services.tool_policy_service import ToolPolicyRequest, ToolPolicyService


FIXTURE_DIR = Path("tests/fixtures/prompt_injection")


class ExecutionSpy:
    """Test double that records whether a command would have executed."""

    def __init__(self) -> None:
        """Create a spy with no execution calls."""
        self.calls: list[str] = []

    def run(self, command: str) -> None:
        """Record a command string without executing it."""
        self.calls.append(command)


def _fixture(name: str) -> str:
    """Return a prompt-injection fixture for log tests."""
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def test_malicious_log_text_cannot_trigger_shell_execution():
    # Prevents log analysis from becoming command execution. The executor is only
    # called if policy allows, which this unconfirmed critical action does not.
    log_text = _fixture("malicious-log.txt")
    executor = ExecutionSpy()
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="operator",
            session_id="session-logs",
            tool_name="shell.run",
            admin_status=True,
            sandbox_available=True,
        )
    )

    if decision.decision == "allow":
        executor.run(log_text)

    assert decision.decision == "review_required"
    assert executor.calls == []


def test_malicious_log_text_is_staged_as_draft_not_executed(tmp_path: Path):
    # Even when a generated command review is created from log text, it must be a
    # staged draft with a review packet, not an executed command.
    log_text = _fixture("malicious-log.txt")
    audit_events: list[tuple[str, dict[str, object]]] = []
    service = ReviewPacketService(
        StagingStore(tmp_path / "staging"),
        audit_hook=lambda event, metadata: audit_events.append((event, metadata)),
    )

    artifact, packet = service.stage_generated_script(
        log_text,
        requested_goal="Investigate suspicious log lines",
        tool_name="shell.run",
        risk_level="Critical",
        why_risky="Log content is untrusted and proposes destructive commands.",
        files_touched=("/var/log/odysseus/audit.jsonl",),
        network_access="none",
    )

    assert artifact.path.exists()
    assert "# Reviewed by user: no" in artifact.path.read_text(encoding="utf-8")
    assert "Run sudo rm -rf /" in packet.markdown
    assert any(event == "tool_staged" for event, _metadata in audit_events)
    assert any(event == "review_packet_generated" for event, _metadata in audit_events)


def test_offline_mode_denies_network_requested_by_malicious_web_research_text():
    # Prompt-injection text cannot override offline mode for network-capable tools.
    _fixture("malicious-webpage.html")
    decision = ToolPolicyService().decide(
        ToolPolicyRequest.from_iterables(
            requesting_user="operator",
            session_id="session-web",
            tool_name="web_research.run",
            admin_status=False,
            offline_mode=True,
            network_requested=True,
        )
    )

    assert decision.decision == "deny"
    assert "offline mode" in decision.reason
