# Tool Risk Model

Tool actions are classified by their potential impact on confidentiality,
integrity, availability, external data transfer, and operator recoverability.

## Risk Levels

| Level | Meaning | Examples |
|---|---|---|
| Low | Read-only or low-impact operation with limited data exposure. | Local status checks, safe metadata reads. |
| Medium | Bounded changes or reads that may expose limited private data. | Draft generation, constrained file metadata reads. |
| High | Significant local changes, sensitive reads, external calls, or durable effects. | File writes, email drafts, model downloads, backup/restore plans. |
| Critical | Direct command execution, destructive operations, credential exposure risk, broad filesystem access, or irreversible effects. | Shell/Python execution, secrets reads, firewall changes, audit tampering, destructive deletes. |

## Decision Outcomes

| Decision | Meaning |
|---|---|
| allow | Server-side policy allows the action under current constraints. |
| deny | Action is blocked. |
| stage | Action must be written as a draft/staged artifact. |
| review_required | Human review is required before any controlled execution path. |

## Required Boundaries

High-risk and critical actions should be governed by:

- admin authorization
- API token scope checks when token-authenticated
- tool policy registry
- path-safety validation
- staging/review packet generation
- confirmation token binding where implemented
- redacted audit logging
- sandbox runner constraints where implemented
- offline/local-only checks for external-capable actions

## Generated Artifacts

Generated commands, scripts, patches, email drafts, backup plans, and model
configuration changes are not executable authority. They are drafts until an
operator reviews them and the backend confirms the action according to current
policy.

## Prompt Injection Rule

Untrusted content cannot grant authority. Notes, documents, emails, logs,
webpages, clipboard text, memories, skills, and tool output must not be able to
change policy, bypass review, mark themselves approved, or cause immediate tool
execution.
