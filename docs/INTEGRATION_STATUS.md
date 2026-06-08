# Odysseus Integration Status

This matrix records the current operational status of Odysseus integrations. It
is intentionally conservative: an integration is not marked supported unless the
project has an explicit setup path, documented failure mode, and tests or manual
validation covering the expected local/operator flow.

Status labels:

- `supported`: documented and expected to work for the stated platform/scope.
- `partial`: useful functionality exists, but setup or failure handling is incomplete.
- `experimental`: available for advanced operators; behavior may change.
- `planned`: intended, but not implemented or not wired end-to-end.
- `unsupported`: not supported by the current alpha boundary.

| Integration | Status | Setup required | Tested platforms | Known issues | Failure mode | Disable behavior | Offline behavior |
|---|---|---|---|---|---|---|---|
| Ollama | partial | Local Ollama service and model installed by operator | Linux/manual local validation only unless CI says otherwise | Model availability and endpoint health vary by host | Endpoint unavailable, model missing, or timeout | Hide/mark disabled when endpoint is not configured | Allowed when endpoint is local and URL policy permits it |
| llama.cpp | experimental | Operator-managed binary/server and local model files | Not broadly validated | Build flags, GPU acceleration, and model format vary | Binary missing, incompatible model, or process failure | Mark unavailable when binary/server is absent | Allowed for local-only serving with local files |
| vLLM | experimental | Python environment, compatible GPU stack, local/downloaded model | Not broadly validated | GPU/CUDA compatibility and memory pressure | Import/startup failure, OOM, model load failure | Mark unavailable when dependencies or hardware are absent | Local serving allowed; external downloads blocked |
| SGLang | planned | Not yet standardized | Not tested | Integration not currently reliable enough to claim support | Not configured / not implemented | Disabled unless explicitly implemented | External actions blocked in offline mode |
| LM Studio | partial | Local LM Studio OpenAI-compatible server | Local operator validation only | Endpoint/model naming differs by operator setup | Endpoint unavailable or model not loaded | Mark disabled when endpoint is absent | Allowed when endpoint is local and URL policy permits it |
| ChromaDB | partial | Local ChromaDB storage or embedded configuration | Linux/local alpha | Index compatibility and backup boundaries need operator care | Storage unavailable or schema/index mismatch | Disable document retrieval features that require it | Local storage remains allowed |
| SearXNG | partial | Local or explicitly configured SearXNG endpoint | Linux/local alpha | External search depends on operator configuration | Endpoint unavailable or blocked by offline mode | Disable web research/search features | Blocked when offline mode is enabled unless fully local and permitted |
| ntfy | partial | Local or remote ntfy endpoint and topic | Linux/local alpha | Remote ntfy is external network dependency | Endpoint unavailable or auth failure | Notifications disabled when not configured | Remote ntfy blocked in offline mode; local endpoint may be allowed |
| IMAP/SMTP | partial | Mail server settings and credentials | Linux/local alpha | Provider auth and mailbox semantics vary | Auth failure, connection timeout, provider rejection | Email features disabled when settings are absent | External mail access blocked in offline/local-only mode |
| CalDAV | partial | Calendar server URL and credentials | Linux/local alpha | Provider URL differences and auth failures | Auth failure or calendar discovery failure | Calendar features disabled when settings are absent | External calendar access blocked in offline/local-only mode |
| OpenAI | partial | API key and provider configuration | Mock-tested only in CI | External provider availability and billing | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| OpenRouter | partial | API key and provider configuration | Mock-tested only in CI | Model routing and provider-specific failures | Auth failure, rate limit, upstream provider error | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| Anthropic | partial | API key and provider configuration | Mock-tested only in CI | API/model availability changes externally | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| Gemini | partial | API key and provider configuration | Mock-tested only in CI | API/model availability changes externally | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| Groq | partial | API key and provider configuration | Mock-tested only in CI | API/model availability changes externally | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| xAI | partial | API key and provider configuration | Mock-tested only in CI | API/model availability changes externally | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| DeepSeek | partial | API key and provider configuration | Mock-tested only in CI | API/model availability changes externally | Auth failure, rate limit, provider outage | Hidden/disabled when key absent | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |
| Local OpenAI-compatible endpoints | partial | Local endpoint URL and model name | Linux/local alpha | Endpoint must be constrained by URL policy | Endpoint unavailable, unsafe URL, or model missing | Disabled when URL is absent or unsafe | Allowed when endpoint is local and URL policy permits it |
| Hugging Face model downloads | experimental | Explicit operator approval, network access, sufficient disk, optional token | Not broadly validated | Large downloads, auth, cache path, disk pressure | Download blocked, auth failure, timeout, disk exhaustion | Disabled when not configured or policy denies | Blocked when `ODYSSEUS_OFFLINE_MODE=true` |

## Operational notes

- Provider probing must never call real external APIs in CI.
- Local endpoints should be treated as local only after URL policy checks.
- Model downloads and model serving are high-risk actions and must remain behind
  tool policy, confirmation/review, audit, path safety, and offline-mode checks.
- Failure messages should be actionable and redacted: command, working directory,
  exit code, bounded stdout/stderr excerpts, log path, likely cause, and a next
  action are useful; raw provider keys, tokens, `.env`, `.app_key`, private
  prompts, or private documents are not.

<!-- ISSUE22_RELEASE_GOVERNANCE:START -->
## Release-Governance Checkpoint Note

The Issue 22 checkpoint did not add new integrations. Existing integration
statuses remain conservative. Provider probing and Cookbook/model-serving
reliability helpers are present, but broad hardware/provider validation is still
partial. External providers remain blocked by implemented offline-mode gates
when `ODYSSEUS_OFFLINE_MODE=true`; local endpoints are allowed only when URL
policy permits them.
<!-- ISSUE22_RELEASE_GOVERNANCE:END -->
