# Hardened Linux Deployment Profile

## Purpose

This document describes an optional advanced Linux deployment profile for Odysseus operators who want stronger host-level isolation than the default cross-platform install.

This is not the default install path. It assumes a technically competent Linux operator who understands systemd units, Unix permissions, service users, reverse proxies, backups, and operational rollback.

This profile reduces blast radius; it does not make Odysseus safe for unauthenticated public internet exposure.

## Threat model

This profile is designed to reduce damage from:

- compromised web application process
- unsafe generated commands that reach the runner boundary
- model-serving process compromise
- accidental disclosure of documents, prompts, diagnostics, or audit logs
- over-broad service permissions
- world-readable or world-writable internal sockets
- worker processes writing directly to audit logs

This profile does not defend against:

- malicious root on the host
- kernel compromise
- vulnerable GPU drivers
- physical attacker access
- intentionally granted operator shell access
- public unauthenticated exposure
- Docker socket access granted to Odysseus services

## Required operator skill level

Use this profile only if you can safely manage:

- Linux users and groups
- POSIX permissions
- systemd service hardening
- reverse proxy and TLS configuration
- log rotation
- backups and restores
- rollback after failed deploys

## Service users and groups

Suggested service identities:

| Service identity | Purpose | Notes |
|---|---|---|
| `odysseus-web` | Web/API process and policy broker | May append audit events if it owns the audit writer role. |
| `odysseus-runner` | Controlled command/script runner | Must not read documents by default. |
| `odysseus-model` | Local model-serving process | May access model cache and GPU devices when explicitly granted. |
| `odysseus-indexer` | Optional indexing process | Grant document/index access only if needed. |
| `odysseus-diagnostics` | Read-only diagnostics collector | Must be command-allowlisted and redacted. |

Do not give any Odysseus service:

- `sudo`
- root runtime
- `docker` group membership by default
- `disk`, `adm`, or broad `systemd-journal` access by default
- `/var/run/docker.sock`
- broad `/home` access
- write access to `/etc`
- direct audit-log write access except the designated audit writer

## Directory layout

Suggested layout:

| Path | Purpose |
|---|---|
| `/srv/odysseus/app/` | Application checkout or release artifact. |
| `/srv/odysseus/imports/` | Operator-provided import staging. |
| `/srv/odysseus/workspaces/` | Tool workspaces. |
| `/srv/odysseus/documents/` | Private documents. |
| `/srv/odysseus/diagnostics/` | Redacted diagnostics output. |
| `/srv/odysseus/prompts/` | Prompt templates or operator-approved prompt assets. |
| `/srv/odysseus/index/` | Search/vector/index state. |
| `/srv/odysseus/staging/generated-scripts/` | Generated scripts waiting for review. |
| `/srv/odysseus/staging/file-patches/` | Generated patch drafts. |
| `/srv/odysseus/staging/command-reviews/` | Command review packets. |
| `/srv/odysseus/staging/rejected/` | Rejected staged artifacts. |
| `/srv/odysseus/models/` | Local model files. |
| `/srv/odysseus/cache/` | Model/runtime cache. |
| `/srv/odysseus/backups/` | Local backup archives. |
| `/var/log/odysseus/app.log` | Web/API logs. |
| `/var/log/odysseus/runner.log` | Runner logs. |
| `/var/log/odysseus/model.log` | Model-serving logs. |
| `/var/log/odysseus/diagnostics.log` | Diagnostics logs. |
| `/var/log/odysseus/audit.jsonl` | Append-only audit events. |
| `/run/odysseus/broker.sock` | Internal broker socket. |
| `/run/odysseus/runner.sock` | Runner socket. |
| `/run/odysseus/model.sock` | Model socket. |

## Ownership model

Suggested ownership:

| Path | Owner/group | Required access model |
|---|---|---|
| `/srv/odysseus/app` | `root:odysseus-web` | Read-only to app runtime. |
| `/srv/odysseus/workspaces` | `odysseus-web:odysseus-runner` | Web brokers tasks; runner writes only controlled workspace output. |
| `/srv/odysseus/staging` | `odysseus-web:odysseus-runner` | Generated artifacts are drafts awaiting review. |
| `/srv/odysseus/documents` | `odysseus-web:odysseus-web` | Runner has no access unless explicitly granted for a reviewed task. |
| `/srv/odysseus/models` | `odysseus-model:odysseus-model` | Model process owns model files. |
| `/srv/odysseus/cache` | `odysseus-model:odysseus-model` | Model cache isolated from web and runner. |
| `/var/log/odysseus/audit.jsonl` | `odysseus-web:odysseus-web` | Only the designated audit writer appends. |
| `/run/odysseus/runner.sock` | `odysseus-runner:odysseus-web` | Mode `0660`; not world-readable/writable. |
| `/run/odysseus/model.sock` | `odysseus-model:odysseus-web` | Mode `0660`; not world-readable/writable. |

## Systemd unit examples

Example units live under `deploy/systemd/`:

- `odysseus-web.service`
- `odysseus-runner.service`
- `odysseus-model.service`
- `odysseus-diagnostics.service`
- `sysusers.conf`
- `tmpfiles.conf`

These examples are starting points. Review them before copying into `/etc/systemd/system/` or `/etc/tmpfiles.d/`.

Common hardening options used by the example units:

- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `RestrictSUIDSGID=true`
- `LockPersonality=true`
- `MemoryDenyWriteExecute=true`
- `CapabilityBoundingSet=`
- `AmbientCapabilities=`
- `SystemCallArchitectures=native`

## Runner isolation

The runner service uses `User=odysseus-runner` and `Group=odysseus-runner`.

By default, the runner example can write only to:

- `/srv/odysseus/workspaces`
- `/srv/odysseus/staging`

It explicitly denies access to:

- `/srv/odysseus/documents`
- `/srv/odysseus/app/.env`
- `/srv/odysseus/app/.app_key`
- `/var/log/odysseus/audit.jsonl`
- `/var/run/docker.sock`

The runner must not be a member of the `docker` group. Generated scripts and commands remain drafts until the policy, review, confirmation, audit, and runner layers approve them.

## Model worker isolation

The model worker uses `User=odysseus-model` and `Group=odysseus-model`.

It may write to:

- `/srv/odysseus/models`
- `/srv/odysseus/cache`
- `/var/log/odysseus/model.log`

Model serving should receive broker-selected context only. It must not have direct arbitrary filesystem access, clipboard access, diagnostics access, or worker/tool access.

GPU access is hardware- and distribution-specific. Grant GPU device access only to the model service, only when required, and document the exact device nodes and groups granted. Do not grant `docker` or broad device access as a shortcut.

## Diagnostics collector isolation

The diagnostics service uses `User=odysseus-diagnostics` and `Group=odysseus-diagnostics`.

It should be read-only over `/srv/odysseus` and `/var/log/odysseus`, with write access only to `/srv/odysseus/diagnostics` for redacted bundles.

Diagnostics must stay human-triggered, redacted, and command-allowlisted. It must not run arbitrary shell commands.

## Unix socket guidance

Internal services should prefer restricted Unix sockets over unauthenticated localhost ports:

| Socket | Owner/group | Mode | Purpose |
|---|---|---:|---|
| `/run/odysseus/broker.sock` | `odysseus-web:odysseus-web` | `0660` | Web/policy broker. |
| `/run/odysseus/runner.sock` | `odysseus-runner:odysseus-web` | `0660` | Runner broker socket. |
| `/run/odysseus/model.sock` | `odysseus-model:odysseus-web` | `0660` | Model server socket. |

Rules:

- sockets must have explicit owner, group, and mode
- runner socket must not be world-readable or world-writable
- model socket must not be world-readable or world-writable
- web process may call runner/model sockets only through policy-controlled broker logic

## Backup and restore considerations

Before applying this profile:

1. Run `scripts/odysseus-backup create <archive>`.
2. Run `scripts/odysseus-backup verify <archive>`.
3. Confirm `.app_key` handling is understood.
4. Confirm restore rollback paths are documented.

Backups should be written to `/srv/odysseus/backups` or an operator-managed secure backup path. Do not allow the runner to write backup archives.

## Audit log considerations

The audit log is security-sensitive. Workers should not write it directly. Prefer a designated audit writer owned by the web/policy broker or an audit-owned component.

Recommended audit file:

- `/var/log/odysseus/audit.jsonl`
- owner: `odysseus-web:odysseus-web`
- mode: `0640`

Runner, model, and diagnostics services should not be able to append to audit logs directly.

## Reverse proxy and network exposure

This profile does not replace reverse proxy and TLS requirements. Public internet exposure still requires:

- TLS
- strong authentication
- explicit host allowlist or trusted reverse proxy headers
- rate limiting where appropriate
- log review
- update strategy
- backup/restore validation

Do not expose Odysseus unauthenticated on the public internet.

## Rollback instructions

To roll back this hardening profile:

1. Stop the hardened services.
2. Restore previous systemd unit files or disable the example units.
3. Restore previous directory ownership from backup notes.
4. Run `systemctl daemon-reload`.
5. Start the previous deployment path.
6. Verify `/api/health`.
7. Verify backup/restore still works.

Example:

```bash
sudo systemctl stop odysseus-web odysseus-runner odysseus-model odysseus-diagnostics
sudo systemctl disable odysseus-web odysseus-runner odysseus-model odysseus-diagnostics
sudo systemctl daemon-reload
```

## Unsupported configurations

Unsupported for this profile:

- running Odysseus services as root
- granting Docker socket access to Odysseus services
- putting services in the `docker` group by default
- granting broad `/home` access
- letting the runner read documents by default
- letting workers append audit logs directly
- unauthenticated public internet exposure
- privileged containers
- Kubernetes deployment assumptions
- automatic GPU driver installation

## Validation checklist

Before considering this profile active:

- `odysseus-runner` cannot write `/var/log/odysseus/audit.jsonl`.
- `odysseus-runner` cannot read `/srv/odysseus/documents` unless explicitly granted.
- `odysseus-runner` can write `/srv/odysseus/staging/generated-scripts`.
- `odysseus-model` can write `/srv/odysseus/models` and `/srv/odysseus/cache`.
- diagnostics output is redacted.
- internal sockets are not world-writable.
- no service has `sudo`, `docker`, `disk`, or broad journal access.
- default install and Docker Compose behavior are unchanged.
