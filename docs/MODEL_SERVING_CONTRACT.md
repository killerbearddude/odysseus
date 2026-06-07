# Odysseus Model-Serving Contract

This document defines the safety contract for local and self-hosted model
serving in Odysseus. The model server is a compute component, not an authority
boundary. It must receive broker-selected context only and must not gain direct
access to tools, secrets, diagnostics, clipboard content, or arbitrary files.

## Authority boundary

- The browser and model are not the authority boundary.
- Model download and model serve actions must go through the tool-policy layer.
- High-risk model actions require human review/confirmation where policy requires it.
- Policy decisions should be auditable and redacted.
- Offline mode blocks external model downloads and external provider probing.

## Filesystem contract

- Model caches must live under approved model/cache roots.
- Arbitrary filesystem paths are not accepted from model output.
- The model server must not receive direct access to `.env`, `.app_key`, SSH/GPG
  material, browser cookies, uploaded private documents, or raw diagnostics.
- Any import/download path should be canonicalized and checked with path-safety
  helpers before use.

## Context contract

- The broker selects which messages, documents, and tool results are sent to the
  model server.
- The model server must not read clipboard data, diagnostics, audit logs, or
  source files directly.
- Prompt-injection content remains untrusted context and cannot grant authority.

## Process and device contract

- Starting a model server is a high-risk action because it starts processes,
  consumes resources, and may expose network endpoints.
- Launches must not bypass policy, staging/review, audit logging, sandbox runner
  constraints, or offline-mode checks.
- GPU/device access should be granted only to model-serving components that need
  it and should not imply access to Docker socket, sudo, host secrets, or broad
  filesystem roots.

## Logging contract

- Logs should be redacted by default.
- Logs must not contain provider keys, Hugging Face tokens, `.env`, `.app_key`,
  session tokens, raw prompts by default, private documents, or raw email bodies.
- Failure diagnostics should include bounded, redacted stdout/stderr excerpts and
  a recommended next action.

## Offline behavior

When `ODYSSEUS_OFFLINE_MODE=true`:

- External model providers are blocked.
- Hugging Face/model downloads are blocked.
- External model metadata lookups are blocked.
- Local model serving may remain available when it does not require external
  network access and uses approved local paths.
