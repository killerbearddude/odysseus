# Deployment Modes

## Supported Private-Alpha Modes

| Mode | Status | Notes |
|---|---|---|
| Localhost development | supported | Suitable for trusted single-user development. |
| Private LAN/VPN with auth and TLS/proxy | partial | Requires operator hardening and backups. |
| Docker Compose private deployment | partial | CI has smoke coverage, but local host Docker must work. |
| Native Linux service deployment | partial | Advanced operators may use documented systemd examples. |
| Hardened Linux profile | experimental | Optional blast-radius reduction, not default behavior. |
| Offline/local-only operation | partial | Implemented gates exist; not a full firewall. |

## Unsupported Modes

- Public unauthenticated internet exposure.
- Hostile multi-tenant SaaS operation.
- Running as root by default.
- Granting Docker socket access by default.
- Exposing internal services or worker/model sockets to untrusted networks.
- Treating external provider processing as local/private processing.

## Operator Requirements

A serious deployment should have:

- authentication enabled
- TLS or a trusted private access layer
- backup/restore validation
- known rollback path
- local data and secrets excluded from source control
- provider credentials scoped and rotated when exposed
- logs reviewed and redacted before sharing
- updates tested on a staging copy where possible

## Checkpoint Note

During the Issue 22 checkpoint, full Python and JavaScript validation passed,
full pytest passed, and focused security suites passed. Docker smoke must be
rerun on a Docker-ready host, and distcheck must be rerun from a clean tree or
worktree before tagging.
