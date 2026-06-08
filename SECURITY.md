# Security Policy

Odysseus is private-alpha software for trusted private deployments. It is a
self-hosted AI workspace with privileged local capabilities, including tools
that can read files, write files, run commands, send email, manage model
serving, and operate local integrations when an operator enables them.

Odysseus is **not intended for unauthenticated public internet exposure**. Treat
it like an admin console. A network-accessible deployment requires strong
authentication, TLS, a trusted reverse proxy or private access layer, careful
backup discipline, and regular updates.

## Supported Versions

Security fixes are handled on the default branch until formal releases are cut.
Public alpha tags should only be created after the release checklist and known
risks documents have been updated.

## Security Model

- The model is treated as untrusted. LLM output is not an authority boundary.
- The browser/UI is not the authority boundary. Server-side policy gates must
  decide whether a tool/action is allowed, denied, staged, or requires review.
- High-risk tools are governed by the policy registry, path safety, staging and
  review packets, confirmation tokens where implemented, audit logging,
  sandbox-runner checks where implemented, and offline/local-only gates.
- Generated scripts, shell commands, patches, email drafts, backup/restore
  actions, and model-serving changes are drafts until reviewed by an operator.
- External integrations may send request data to configured providers. Operators
  are responsible for understanding provider terms, retention, billing, and
  data-handling behavior.

## Deployment Guidance

- Keep `AUTH_ENABLED=true` for any network-accessible deployment.
- Keep `LOCALHOST_BYPASS=false` outside local development.
- Set `SECURE_COOKIES=true` when Odysseus is served through HTTPS by a trusted
  reverse proxy or private access gateway.
- Use HTTPS when exposing the app beyond localhost.
- Put Odysseus behind a trusted reverse proxy or private access layer such as a
  VPN, Tailscale, or Cloudflare Access.
- Keep ChromaDB, SearXNG, ntfy, Ollama, vLLM, llama.cpp, databases, and raw
  model/provider APIs internal-only.
- Do not expose local model APIs or worker sockets directly to the internet.
- Use `ODYSSEUS_OFFLINE_MODE=true` only as an implemented local-only control;
  do not assume it blocks features that have not been wired to the helper yet.

## Secret and Data Protection

Protect these paths and values:

- `.env`
- `.app_key`
- `data/`
- `logs/`
- uploaded files
- generated media
- backups
- auth/session files
- SQLite databases
- API keys and model/provider tokens
- email/calendar credentials
- SSH/GPG keys
- browser cookies
- private documents and prompts

Never commit live `.env` values, local databases, uploaded files, generated
media, logs, backups, auth/session files, API keys, model/provider tokens,
password hashes, or private documents.

## Admin Tools

Leave high-risk agent tools restricted to admins:

- shell and Python execution
- file read/write
- email send/read/delete
- calendar write actions
- MCP tools
- app API and internal admin routes
- task, skill, memory, and settings management
- token and webhook management
- backup/restore
- model download and model serving
- diagnostics/support bundle export

Powerful local admin tools remain dangerous. Trusted users can intentionally or
accidentally damage local data.

## Offline / Local-Only Mode

Offline mode blocks implemented external-capable provider, search, download,
and network paths that call the centralized helper/policy checks. It is a
safety gate, not a firewall and not a proof that no process on the host can make
network connections. Pair offline mode with OS/container/network controls when
strict egress prevention is required.

## Reporting

Report vulnerabilities privately via GitHub security advisories if available, or
open a minimal issue that does not disclose exploit details. Do not post working
exploit chains, real credentials, private logs, or private documents in public
issues.
