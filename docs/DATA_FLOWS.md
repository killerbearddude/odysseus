# Data Flows

This document summarizes the high-level data flows that matter for private-alpha
security review.

## Browser to Web/API

The browser sends chat messages, document actions, settings changes, review
packet interactions, diagnostics requests, and other UI/API operations to the
Odysseus web/API process. The browser is not the authority boundary; server-side
authentication, authorization, policy, path safety, and confirmation checks must
make final decisions.

## User Content to Model Context

User prompts, documents, notes, memories, skills, web pages, email bodies,
logs, clipboard text, and tool output may become model context. Untrusted
content must remain data and must not grant tool authority, bypass confirmation,
or mark actions approved.

## Model Output to Tool Boundary

Model output may propose tool calls, commands, patches, scripts, email drafts,
model changes, or backup/restore actions. High-risk proposals must pass through
the tool policy registry, staging/review packet flow, audit logging, path safety,
offline-mode checks, and runner constraints where implemented.

## Staging and Review

Generated artifacts are written as drafts under controlled staging paths. Review
packets summarize requested goal, tool, risk, proposed checks, proposed changes,
files touched, network access, commands not approved, required backup/snapshot,
verification, rollback, and human decision state.

## Audit Data

Tool audit events record redacted metadata about decisions and failures. They
must not store raw provider keys, passwords, session tokens, SSH/GPG keys,
browser cookies, full private documents, full prompts by default, or raw email
bodies.

## Diagnostics and Support Bundles

Diagnostics and support bundles are human-triggered and read-only. They include
redacted configuration, health, version, policy, runner, and audit summaries.
They must not include raw `.env`, `.app_key`, uploaded files, private documents,
email contents, raw prompts by default, or provider tokens.

## External Providers

External providers may receive prompts, metadata, documents, search queries,
email/calendar data, or model-download requests depending on configuration.
Offline mode blocks implemented external-capable gates but is not a host-level
network firewall.

## Backup and Restore

Backups may contain sensitive local state, including databases, uploads,
generated files, `.app_key`, `.env`, audit data, staging artifacts, and model or
index state. Archives must be verified before restore and never committed.
