# Known Risks

This document records risks accepted or deferred for the private-alpha boundary.
It should be reviewed before any public alpha tag.

## Accepted Private-Alpha Risks

- Odysseus is powerful local admin software. Trusted admins can intentionally
  damage local data.
- Public unauthenticated exposure is unsupported.
- The app is moving quickly; operators should expect rough edges and validate
  backups before upgrades.
- Some controls are implemented as guardrails for intended flows, not as a
  complete hostile multi-tenant isolation layer.

## Known Incomplete Controls

- Sandbox runner: safe local runner abstraction exists, but there is no full
  Docker/firejail/nsjail-style sandbox, no kernel-level policy, and no complete
  network egress firewall.
- Offline mode: implemented gates block known external-capable paths, but it is
  not a host firewall and cannot prove all host processes are offline.
- Frontend safety UX: render helpers exist; complete product UI wiring and
  server-backed approval screens can still improve.
- Dependency audits: `pip-audit` was not installed during the Issue 22
  checkpoint; dependency reproducibility/audit work should be a follow-up.
- Distcheck must be rerun from a clean tree/worktree after generated Python
  bytecode is removed.
- Docker smoke must be rerun on a host with a working Docker daemon.

## Unsupported Deployment Modes

- Public unauthenticated internet exposure.
- Hostile multi-tenant SaaS operation.
- Running Odysseus as root for normal operation.
- Granting Odysseus sudo or broad host access as a default path.
- Giving Odysseus the Docker socket or `docker` group by default.
- Exposing ChromaDB, SearXNG, ntfy, Ollama, local model servers, databases, or
  worker sockets directly to untrusted networks.

## External Integration Risks

- External model providers receive configured request data.
- External search, email, calendar, notification, and model-download providers
  may receive metadata and content depending on operator configuration.
- Provider availability, pricing, retention, and safety behavior can change
  independently of Odysseus.
- Offline mode blocks implemented gates, but operators needing strict egress
  prevention should add OS/container/network controls.

## Admin Tool Risks

- Shell/Python execution can destroy files, leak secrets, install malicious
  packages, or modify the host if approved by an operator.
- File read/write tools can expose private documents if policy/path checks are
  bypassed or miswired in future changes.
- Email/calendar tools can send, delete, or alter real user data if granted.
- MCP tools and app API tools can bridge into other capabilities and must remain
  gated.

## Model and Provider Risks

- Local models can follow prompt-injection instructions even when untrusted data
  is labeled; policy boundaries must not rely on model compliance.
- Local model servers may log prompts or expose endpoints unless configured
  carefully.
- Provider probes and Cookbook helpers are tested with mocks in CI; broad
  hardware/provider validation remains incomplete.

## Backup and Restore Risks

- Backups may contain databases, uploads, generated media, private documents,
  `.env`, `.app_key`, provider settings, and audit data.
- Backup archives must never be committed or shared publicly.
- Restoring a database without the matching `.app_key` or auth/session state may
  break login or encrypted data assumptions.
- Operators should verify archives before restore and take a pre-restore backup.

## Sandbox Limitations

- The current runner abstraction constrains working directory, environment,
  timeout, and output limits for intended runner use.
- It is not a complete OS sandbox, not a VM, not a container boundary, and not a
  firewall.
- A hardened Linux deployment profile can reduce blast radius but must be
  applied correctly by an operator.

## Recommended Operator Mitigations

- Keep Odysseus private and authenticated.
- Use TLS and a trusted reverse proxy/private access layer for any networked
  deployment.
- Maintain tested backups before upgrades, migrations, imports, or model/index
  changes.
- Keep `.env`, `.app_key`, databases, uploads, logs, and backups out of Git.
- Use offline mode plus OS/network controls when strict local-only operation is
  required.
- Review staged scripts, patches, email drafts, backup plans, and model-serving
  changes before execution.
- Run release checklist validation before tagging or publishing builds.
