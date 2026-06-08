# Changelog

<!-- ISSUE22_RELEASE_GOVERNANCE:START -->
## Unreleased

### Release governance checkpoint

- Recorded release-governance posture after hardening/security UX work through
  PR #20.
- Full pytest baseline on `White-Queen` passed: 2703 passed, 1 skipped, 1
  xfailed, 43 warnings.
- Python compileall, JavaScript syntax, executable-bit check, release manifest
  generation, focused security suites, and npm audit passed.
- `pip-audit` was not run because the tool was not installed.
- `distcheck` must be rerun from a clean tree/worktree before tagging because
  the checkpoint run found generated `__pycache__`/`.pyc` files after compile
  and test commands.
- Docker smoke must be rerun on a host with a working Docker daemon before
  tagging; the checkpoint host could not connect to Docker/compose.
<!-- ISSUE22_RELEASE_GOVERNANCE:END -->
