# Release Checklist

Use this checklist before public alpha tags. Check items only after validating
on a clean branch or a clean temporary worktree.

## Repository State

- [ ] Branch is the intended release branch.
- [ ] `git status --short` is clean.
- [ ] Open pull requests reviewed or intentionally deferred.
- [ ] Recent merged PRs reviewed for release notes.
- [ ] `RELEASE_MANIFEST.json` generated from the release candidate.
- [ ] Local data, logs, uploads, generated media, databases, and secrets are
      excluded.

## Baseline Validation

- [ ] Python syntax check passes:
      `python -m compileall -q app.py core routes src services scripts tests`
- [ ] JavaScript syntax check passes:
      `find static -name '*.js' -print0 | xargs -0 -r -n1 node --check`
- [ ] Full unit/security suite passes: `python -m pytest`
- [ ] Executable-bit check passes: `scripts/check-executable-bits.sh`
- [ ] Release manifest generation passes:
      `python scripts/generate-release-manifest.py`
- [ ] `scripts/distcheck.sh` passes from a clean tree or clean worktree.
- [ ] `scripts/docker-smoke.sh` passes on a host with a working Docker daemon.

## Security-Focused Validation

- [ ] Tool policy registry tests pass.
- [ ] Tool policy service tests pass.
- [ ] Tool policy invariant tests pass.
- [ ] Path safety tests pass.
- [ ] Tool audit tests pass.
- [ ] Audit redaction tests pass.
- [ ] Review packet tests pass.
- [ ] Confirmation token tests pass.
- [ ] Prompt-injection tests pass.
- [ ] Offline-mode tests pass.
- [ ] Diagnostics/support-bundle tests pass.
- [ ] Sandbox/runner tests pass or unsupported platform limitations are
      documented.

## Data Safety

- [ ] Migration tests pass.
- [ ] Backup/restore tests pass.
- [ ] Backup/restore smoke command has been run or explicitly deferred.
- [ ] `docs/BACKUP_RESTORE.md` reflects the current archive format and restore
      warnings.
- [ ] Data-loss risks are documented in `docs/KNOWN_RISKS.md`.

## Documentation

- [ ] `README.md` release posture is current.
- [ ] `SECURITY.md` is current.
- [ ] `THREAT_MODEL.md` is current.
- [ ] `ROADMAP.md` marks completed and remaining work accurately.
- [ ] `CHANGELOG.md` includes release-governance notes.
- [ ] `docs/DATA_FLOWS.md` is current.
- [ ] `docs/DEPLOYMENT_MODES.md` is current.
- [ ] `docs/TOOL_RISK_MODEL.md` is current.
- [ ] `docs/INTEGRATION_STATUS.md` is current.
- [ ] `docs/HARDENED_LINUX_DEPLOYMENT.md` is current.
- [ ] `docs/KNOWN_RISKS.md` is current.

## Dependency and Supply Chain

- [ ] Dependency pins/constraints are current.
- [ ] Python dependency audit passes or exceptions are documented.
- [ ] Node dependency audit passes or exceptions are documented.
- [ ] Generated release manifest excludes local-only files and includes expected
      source/test/doc assets.

## Issue 22 Checkpoint Evidence

Checkpoint host: `White-Queen`  
Branch checked: `dev`  
HEAD checked: `5ca6494`  
Open PR count: `0`

Observed results:

| Check | Result | Notes |
|---|---:|---|
| Python compileall | pass | Exit 0. |
| JS syntax | pass | Exit 0. |
| Full pytest | pass | 2703 passed, 1 skipped, 1 xfailed, 43 warnings. |
| Executable-bit check | pass | Exit 0. |
| Release manifest generation | pass | `RELEASE_MANIFEST.json` generated. |
| Security-focused suites | pass | All requested focused suites ran. |
| npm audit | pass | 0 vulnerabilities reported. |
| pip-audit | not run | `pip-audit` was not installed. |
| distcheck | fail in dirty test tree | Failed because compileall/test run left `__pycache__`/`.pyc`; rerun in a clean worktree before tagging. |
| Docker smoke | environment fail | Docker/compose could not reach a Docker daemon on the checkpoint host. Rerun on a Docker-ready host before tagging. |
