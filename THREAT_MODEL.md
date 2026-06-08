# Threat Model

Odysseus is a self-hosted AI workspace with privileged local access. This threat
model describes the current private-alpha boundary after the hardening baseline
through the release-governance checkpoint.

## Deployment Assumption

Odysseus is designed for trusted operators on private infrastructure. It is not
safe for unauthenticated public internet exposure. The correct mental model is
an admin console with AI-assisted workflows, not a hostile multi-tenant SaaS
service.

## Trust Boundaries

| Boundary | Current posture |
|---|---|
| Browser/UI | Not authoritative. UI must reflect server decisions, not create authority. |
| LLM/model output | Untrusted. Output can propose actions but cannot grant permissions. |
| Authenticated admin | Trusted to operate powerful local capabilities. |
| Non-admin user | Must not reach admin-only tools or internal privileged routes. |
| External content | Untrusted data. Web pages, email, logs, clipboard text, notes, memories, skills, and documents must not grant tool authority. |
| Local filesystem | Sensitive. Access is constrained through path-safety helpers where wired. |
| External providers | Potential data recipients. Requests may leave the host when configured and not blocked by offline mode. |
| Local model server | Receives broker-selected context only; should not receive arbitrary filesystem/tool access. |
| Sandbox runner | Reduces blast radius but is not a complete security boundary. |

## Control Status Matrix

| Control | Status | Notes |
|---|---|---|
| Authentication | complete | Password/session auth exists for private-alpha use. |
| Setup token | complete | Startup/setup safety checks are implemented. |
| Startup safety checks | complete | Misconfiguration checks are present for current baseline. |
| API token scopes | complete | Central scope registry exists and is tested. |
| Internal tool authorization | complete | Internal admin authorization is centralized. |
| Tool policy registry | complete | Central registry and invariants are tested. |
| Path safety | complete | Canonical helper blocks traversal/common-prefix traps where wired. |
| Audit logging | complete | Redacted SQLite-backed tool audit service exists. |
| Staging/review packets | complete | Generated artifacts can be staged as drafts with review metadata. |
| Prompt-injection negative corpus | complete | Malicious fixtures test untrusted text cannot grant tool authority. |
| Sandbox runner abstraction | partial | Safe local runner abstraction exists; no full container/firewall sandbox yet. |
| Offline mode | partial | Implemented gates block configured external paths; not a host firewall. |
| Diagnostics/support bundle | complete | Admin diagnostics and redacted support bundle helpers exist. |
| Backup/restore | complete | Local SQLite backup/restore discipline exists for alpha boundary. |
| Cookbook/model-serving reliability | partial | Preflight/probe/contract helpers exist; broad hardware validation remains incomplete. |
| Hardened Linux profile | partial | Optional docs/systemd examples exist; not default and not runtime-enforced everywhere. |
| Frontend safety UX | partial | Rendering helpers expose risk/review/diagnostic state; full product UI wiring can continue. |
| Dependency reproducibility/audit | planned | `pip-audit` was not installed during checkpoint; lock/audit work remains. |

## Roles and Capabilities

Admins can intentionally perform dangerous local operations, including command
execution, file changes, provider configuration, email sending, backup/restore,
and model serving. The threat model does not try to prevent trusted admins from
using those capabilities. It does try to prevent unauthenticated users,
non-admins, untrusted text, and generated content from silently escalating into
those capabilities.

## Prompt Injection

External or user-editable content must be treated as data. It must not be
allowed to modify tool policy, mark itself reviewed, bypass confirmation, read
secrets, send email, overwrite logs, or execute shell/Python commands.

## Known Accepted Private-Alpha Risks

- Trusted admins can intentionally destroy local data.
- Local shell and Python tools are inherently dangerous even with staging,
  policy, audit, and runner controls.
- Offline mode is not a host-level egress firewall.
- Local provider/model servers may have their own vulnerabilities.
- Browser-side UI helps operators understand decisions but is not the security
  boundary.
- Optional hardened Linux profile reduces blast radius but does not make the app
  safe for public unauthenticated exposure.

## Unsupported Deployment Modes

- Unauthenticated public internet exposure.
- Hostile multi-tenant operation.
- Running privileged tools for unknown users.
- Granting Odysseus the Docker socket or sudo as a default operating model.
- Treating external model providers as private/local processing.
