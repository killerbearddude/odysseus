#!/usr/bin/env bash
# Release hygiene gate for source distributions and public release artifacts.
#
# This script intentionally fails closed: release candidates must not include a
# dirty Git tree, local secrets, user data, generated uploads, databases, or
# Python bytecode. RELEASE_MANIFEST.json is treated as a generated artifact and
# should remain ignored so manifest generation can run immediately before this
# check without making the tree dirty.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

failures=0

fail() {
  printf 'error: %s
' "$1" >&2
  failures=$((failures + 1))
}

print_matches() {
  local heading="$1"
  shift
  local tmp
  tmp="$(mktemp)"
  "$@" >"$tmp" || true
  if [[ -s "$tmp" ]]; then
    printf 'error: %s
' "$heading" >&2
    sed 's/^/  - /' "$tmp" >&2
    failures=$((failures + 1))
  fi
  rm -f "$tmp"
}

# Fail if any tracked or untracked non-ignored file is present. Generated release
# manifests are ignored via .gitignore so local manifest creation can precede
# distcheck without causing a false dirty-tree failure.
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  fail "git working tree is dirty; commit, stash, or remove local changes before release"
  git status --short >&2 || true
fi

# Root-level environment files and app keys are never release-safe. .env.example
# is explicitly allowed because it documents safe placeholder configuration.
print_matches "local environment/app key files must not be present"   find . -maxdepth 1     \( -name '.env' -o -name '.env.*' -o -name '.app_key' \)     ! -name '.env.example'     -print

# User/state directories are blocked even when ignored by Git because release
# archives are often built from the working tree, not just tracked files.
for dir in data logs uploads generated backups; do
  if [[ -e "$dir" ]]; then
    fail "release-blocking local directory exists: $dir/"
  fi
done

# Search the project tree for database and Python cache artifacts, excluding
# tool/runtime dependency directories that are not part of source releases.
PRUNE_EXPR=(
  -path './.git' -o
  -path './.venv' -o
  -path './venv' -o
  -path './env' -o
  -path './node_modules' -o
  -path './.pytest_cache' -o
  -path './.mypy_cache' -o
  -path './.ruff_cache'
)

print_matches "database files must not be present"   find . \( "${PRUNE_EXPR[@]}" \) -prune -o     -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \)     -print

print_matches "Python __pycache__ directories must not be present"   find . \( "${PRUNE_EXPR[@]}" \) -prune -o     -type d -name '__pycache__'     -print

print_matches "Python bytecode files must not be present"   find . \( "${PRUNE_EXPR[@]}" \) -prune -o     -type f -name '*.pyc'     -print

for doc in README.md SECURITY.md THREAT_MODEL.md ROADMAP.md; do
  if [[ ! -f "$doc" ]]; then
    fail "required release document is missing: $doc"
  fi
done

if ! scripts/check-executable-bits.sh; then
  fail "executable-bit check failed"
fi

if [[ "$failures" -ne 0 ]]; then
  printf '
distcheck failed with %s issue(s).
' "$failures" >&2
  exit 1
fi

printf 'distcheck passed
'
