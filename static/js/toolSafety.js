/*
 * Frontend safety UX render helpers for Odysseus.
 *
 * These helpers render policy decisions, review packets, and diagnostics into
 * escaped HTML strings. They are deliberately side-effect free: no approval,
 * rejection, execution, network request, or backend mutation occurs here.
 */

function normalizeValue(value) {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value);
}

function escapeHtml(value) {
  return normalizeValue(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function titleCase(value) {
  const text = normalizeValue(value).replace(/[_-]/g, " ").trim();
  if (!text) {
    return "Unknown";
  }
  return text.replace(/\b\w/g, (character) => character.toUpperCase());
}

function sentenceCase(value) {
  const text = normalizeValue(value).replace(/[_-]/g, " ").trim();
  if (!text) {
    return "Unknown";
  }
  return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
}

function boolText(value) {
  return value ? "yes" : "no";
}

function boolLabel(value) {
  return value ? "Yes" : "No";
}

function valuesAsList(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return "<li>None requested</li>";
  }
  return values.map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("");
}

function riskClass(risk) {
  const normalized = normalizeValue(risk || "unknown").toLowerCase();
  if (["low", "medium", "high", "critical"].includes(normalized)) {
    return normalized;
  }
  return "unknown";
}

function renderRiskBadge(risk) {
  const normalized = riskClass(risk);
  const label = titleCase(normalized);
  return `<span class="tool-safety-risk-badge tool-safety-risk-${escapeHtml(normalized)}" aria-label="Risk level: ${escapeHtml(label)}">${escapeHtml(label)}</span>`;
}

function renderToolDecision(decisionInput) {
  const decision = decisionInput || {};
  const risk = riskClass(decision.risk);
  const riskLabel = titleCase(risk);
  const decisionText = sentenceCase(decision.decision || "unknown");
  const toolName = decision.tool_name || decision.tool || "unknown";
  const requiredScope = decision.required_scope || decision.api_scope || "none";
  const sandboxAvailable = decision.sandbox_available !== undefined
    ? decision.sandbox_available
    : decision.sandbox_used;
  const requestedPaths = decision.paths_requested || decision.requested_paths || [];

  return `
<section class="tool-safety-card tool-safety-decision tool-safety-risk-${escapeHtml(risk)}" aria-label="Tool safety decision">
  <header class="tool-safety-card-header">
    ${renderRiskBadge(risk)}
    <strong>${escapeHtml(decisionText)}</strong>
    <span class="sr-only">Risk level: ${escapeHtml(riskLabel)}</span>
  </header>
  <dl class="tool-safety-details">
    <dt>Tool</dt><dd>${escapeHtml(toolName)}</dd>
    <dt>Risk level</dt><dd>Risk level: ${escapeHtml(riskLabel)}</dd>
    <dt>Decision</dt><dd>${escapeHtml(decisionText)}</dd>
    <dt>Reason</dt><dd>${escapeHtml(decision.reason || "No reason provided")}</dd>
    <dt>Required API scope</dt><dd>${escapeHtml(requiredScope)}</dd>
    <dt>Admin required</dt><dd>${escapeHtml(boolLabel(decision.admin_required))}</dd>
    <dt>Confirmation required</dt><dd>${escapeHtml(boolLabel(decision.confirmation_required))}</dd>
    <dt>Sandbox required</dt><dd>${escapeHtml(boolLabel(decision.sandbox_required))}</dd>
    <dt>Sandbox available</dt><dd>${escapeHtml(boolLabel(Boolean(sandboxAvailable)))}</dd>
    <dt>Network requested</dt><dd>${escapeHtml(boolLabel(decision.network_requested))}</dd>
    <dt>Audit event ID</dt><dd>${escapeHtml(decision.audit_event_id || decision.audit_id || "not recorded")}</dd>
  </dl>
  <section class="tool-safety-paths" aria-label="Requested paths">
    <h3>Paths requested</h3>
    <ul>${valuesAsList(requestedPaths)}</ul>
  </section>
</section>`.trim();
}

function renderReviewPacket(packetInput, optionsInput) {
  const packet = packetInput || {};
  const options = optionsInput || {};
  const backendConfirmationAvailable = Boolean(options.backendConfirmationAvailable);
  const approved = Boolean(packet.approved || packet.reviewed || packet.confirmed);
  const state = approved ? "Approved" : "Not approved";
  const risk = riskClass(packet.risk);
  const toolName = packet.tool_name || packet.tool || "unknown tool";
  const commands = packet.commands || packet.commands_not_approved || [];
  const filesTouched = packet.files_touched || packet.files || [];

  return `
<section class="tool-safety-card review-packet" aria-label="Action review packet">
  <header class="tool-safety-card-header">
    ${renderRiskBadge(risk)}
    <strong>${escapeHtml(toolName)}</strong>
    <span class="review-state" aria-label="Review state: ${escapeHtml(state)}">${escapeHtml(state)}</span>
  </header>
  <h2>Requested Goal</h2>
  <p>${escapeHtml(packet.requested_goal || packet.goal || "")}</p>
  <h2>Proposed Changes</h2>
  <pre>${escapeHtml(packet.proposed_changes || packet.changes || "")}</pre>
  <h2>Files Touched</h2>
  <ul>${valuesAsList(filesTouched)}</ul>
  <h2>Commands Not Approved</h2>
  <ul>${valuesAsList(commands)}</ul>
  <h2>Verification</h2>
  <pre>${escapeHtml(packet.verification || packet.verification_steps || "")}</pre>
  <h2>Rollback</h2>
  <pre>${escapeHtml(packet.rollback || packet.rollback_steps || "")}</pre>
  <div class="review-actions" aria-label="Human decision controls">
    <button type="button" class="approve-action" ${backendConfirmationAvailable ? "" : "disabled"} aria-disabled="${backendConfirmationAvailable ? "false" : "true"}">Approve</button>
    <button type="button" class="reject-action">Reject</button>
  </div>
</section>`.trim();
}

function renderDiagnosticsPanel(diagnosticsInput) {
  const diagnostics = diagnosticsInput || {};
  const policyStatus = diagnostics.tool_policy_registry || diagnostics.tool_policy || {};
  const runnerStatus = diagnostics.sandbox_runner || diagnostics.runner || {};
  const auditStatus = diagnostics.audit || {};
  const recentDenied = diagnostics.recent_denied_actions || [];
  const recentStaged = diagnostics.recent_staged_actions || [];
  const providerSummary = diagnostics.provider_probe_summary || diagnostics.providers || {};

  return `
<section class="tool-safety-card diagnostics-panel" aria-label="Admin diagnostics panel">
  <p class="read-only-note">Diagnostics are read-only.</p>
  <dl class="tool-safety-details">
    <dt>Health state</dt><dd>${escapeHtml(diagnostics.health_state || diagnostics.health || "unknown")}</dd>
    <dt>Deployment mode</dt><dd>${escapeHtml(diagnostics.deployment_mode || "unknown")}</dd>
    <dt>Offline mode</dt><dd>${escapeHtml(boolText(diagnostics.offline_mode))}</dd>
    <dt>Tool policy registry</dt><dd>${escapeHtml(policyStatus.status || "unknown")}</dd>
    <dt>Sandbox runner</dt><dd>${escapeHtml(runnerStatus.status || "unknown")}</dd>
    <dt>Audit status</dt><dd>${escapeHtml(auditStatus.status || "unknown")}</dd>
    <dt>Provider probe summary</dt><dd>${escapeHtml(providerSummary.status || providerSummary.summary || "not available")}</dd>
  </dl>
  <h3>Recent denied actions</h3>
  <ul>${valuesAsList(recentDenied)}</ul>
  <h3>Recent staged actions</h3>
  <ul>${valuesAsList(recentStaged)}</ul>
</section>`.trim();
}

function preventEnterApproval(event) {
  if (!event || event.key !== "Enter") {
    return false;
  }
  const target = event.target || {};
  const className = normalizeValue(target.className);
  if (className.includes("approve-action")) {
    event.preventDefault();
    return true;
  }
  return false;
}

function bindToolSafetyActions(root) {
  const safeRoot = root || (typeof document !== "undefined" ? document : null);
  if (!safeRoot || typeof safeRoot.addEventListener !== "function") {
    return false;
  }

  safeRoot.addEventListener("click", (event) => {
    const target = event.target;
    if (!target || typeof target.closest !== "function") {
      return;
    }
    const approveButton = target.closest(".approve-action");
    if (approveButton && approveButton.disabled) {
      event.preventDefault();
    }
  });
  return true;
}

const api = {
  escapeHtml,
  titleCase,
  sentenceCase,
  renderRiskBadge,
  renderToolDecision,
  renderReviewPacket,
  renderDiagnosticsPanel,
  preventEnterApproval,
  bindToolSafetyActions,
};

if (typeof globalThis !== "undefined") {
  globalThis.OdysseusToolSafety = api;
}

export {
  escapeHtml,
  titleCase,
  sentenceCase,
  renderRiskBadge,
  renderToolDecision,
  renderReviewPacket,
  renderDiagnosticsPanel,
  preventEnterApproval,
  bindToolSafetyActions,
};
