"""Tests for frontend safety UX static helpers.

These tests are intentionally static/contract-oriented. They prevent regressions
where generated tool actions become color-only, unescaped, auto-approved, or
missing verification/rollback context before a full frontend test harness exists.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_SAFETY_JS = REPO_ROOT / "static" / "js" / "toolSafety.js"
REVIEW_PACKETS_JS = REPO_ROOT / "static" / "js" / "reviewPackets.js"
DIAGNOSTICS_JS = REPO_ROOT / "static" / "js" / "diagnostics.js"


def _node_eval(script: str) -> str:
    """Run a small Node.js assertion script from the repository root."""
    if not shutil.which("node"):
        raise AssertionError("node is required for frontend safety UI tests")
    result = subprocess.run(
        ["node", "-e", script],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def test_static_safety_modules_exist_and_pass_node_syntax():
    # Regression guard: static helpers must remain standalone syntax-valid JS.
    for path in [TOOL_SAFETY_JS, REVIEW_PACKETS_JS, DIAGNOSTICS_JS]:
        assert path.exists(), f"missing {path}"
        subprocess.run(["node", "--check", str(path)], cwd=REPO_ROOT, check=True)


def test_tool_decision_html_includes_text_risk_and_escapes_untrusted_values():
    # Tool names and policy reasons can contain model-supplied or untrusted text.
    script = r"""
const safety = require("./static/js/toolSafety.js");
const html = safety.renderToolDecision({
  tool_name: "shell.run <img src=x onerror=alert(1)>",
  risk: "critical",
  decision: "review_required",
  reason: "<script>alert(1)</script>",
  confirmation_required: true,
  sandbox_required: true,
  network_requested: true,
  paths_requested: ["/srv/odysseus/staging/file.patch"],
  audit_event_id: "audit-123"
});
if (!html.includes("Critical")) throw new Error("risk text missing");
if (!html.includes("Risk level: Critical")) throw new Error("screen-reader risk missing");
if (!html.includes("Review required")) throw new Error("decision text missing");
if (!html.includes("audit-123")) throw new Error("audit event missing");
if (html.includes("<script>") || html.includes("<img")) throw new Error("unescaped HTML present");
process.stdout.write(html);
"""
    html = _node_eval(script)
    assert "Critical" in html
    assert "Risk level: Critical" in html


def test_review_packet_includes_verification_rollback_and_disabled_approval_without_backend():
    # Staged actions must default to not approved and must show validation context.
    script = r"""
const safety = require("./static/js/toolSafety.js");
const html = safety.renderReviewPacket({
  id: "packet-1",
  risk: "high",
  tool_name: "file.write",
  requested_goal: "Apply patch",
  proposed_changes: "<b>danger</b>",
  verification: "python -m pytest",
  rollback: "git restore .",
  commands: ["rm -rf / should stay escaped"]
}, { backendConfirmationAvailable: false });
if (!html.includes("Verification")) throw new Error("verification missing");
if (!html.includes("Rollback")) throw new Error("rollback missing");
if (!html.includes("Not approved")) throw new Error("not-approved state missing");
if (!html.includes("disabled")) throw new Error("approve button should be disabled");
if (html.includes("<b>danger</b>")) throw new Error("generated content was not escaped");
process.stdout.write(html);
"""
    html = _node_eval(script)
    assert "Verification" in html
    assert "Rollback" in html
    assert "Not approved" in html
    assert "disabled" in html


def test_diagnostics_panel_is_read_only_and_displays_offline_and_policy_status():
    # Diagnostics must explain status without exposing mutating service controls.
    script = r"""
const safety = require("./static/js/toolSafety.js");
const html = safety.renderDiagnosticsPanel({
  health_state: "ok",
  deployment_mode: "local",
  offline_mode: true,
  tool_policy_registry: { status: "loaded" },
  sandbox_runner: { status: "available" },
  audit: { status: "enabled" },
  recent_denied_actions: ["shell.run denied"],
  recent_staged_actions: ["file.write staged"]
});
if (!html.includes("Offline mode")) throw new Error("offline mode missing");
if (!html.includes("loaded")) throw new Error("tool policy status missing");
if (!html.includes("read-only")) throw new Error("read-only note missing");
if (html.includes("Restart service") || html.includes("Delete")) throw new Error("mutating controls present");
process.stdout.write(html);
"""
    html = _node_eval(script)
    assert "Offline mode" in html
    assert "read-only" in html


def test_frontend_safety_helpers_do_not_use_inline_event_handlers():
    # Inline handlers make XSS reviews harder and should not appear in helpers.
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [TOOL_SAFETY_JS, REVIEW_PACKETS_JS, DIAGNOSTICS_JS]
    )
    forbidden = [" onclick=", " onerror=", " onload=", " onsubmit=", "javascript:"]
    for marker in forbidden:
        assert marker not in combined.lower()


def test_critical_actions_do_not_auto_approve_on_enter():
    # Approval should require an explicit button click and backend confirmation.
    text = TOOL_SAFETY_JS.read_text(encoding="utf-8")
    assert "addEventListener(\"click\"" in text
    assert "addEventListener(\"keydown\"" not in text
    assert "backendConfirmationAvailable" in text


def test_accessibility_css_mentions_focus_text_risk_and_reduced_motion():
    # Risk state cannot be color-only; keyboard and reduced-motion support matter.
    css_candidates = [
        REPO_ROOT / "static" / "styles.css",
        REPO_ROOT / "static" / "style.css",
        REPO_ROOT / "static" / "css" / "styles.css",
        REPO_ROOT / "static" / "css" / "style.css",
    ]
    css = "\n".join(path.read_text(encoding="utf-8") for path in css_candidates if path.exists())
    assert "ods-risk-critical" in css
    assert "content: \"Risk:" in css
    assert "focus-visible" in css
    assert "prefers-reduced-motion" in css
