#!/usr/bin/env bash
# Verifies that tracked runnable scripts have the executable bit set.
#
# Release archives preserve executable mode from Git. A shebang-bearing file that
# is not executable can work locally when invoked through an interpreter, but fail
# for users or CI when called directly as a script.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

failed=0

# Inspect only tracked files so local build artifacts, virtualenv contents, and
# ignored caches cannot make the release check noisy.
while IFS= read -r -d '' path; do
  [[ -f "$path" ]] || continue

  if head -c 2 "$path" | grep -q '^#!'; then
    if [[ ! -x "$path" ]]; then
      printf 'error: tracked shebang file is not executable: %s
' "$path" >&2
      failed=1
    fi
  fi
done < <(git ls-files -z)

if [[ "$failed" -ne 0 ]]; then
  printf '
Set executable mode with: git update-index --chmod=+x <path>
' >&2
fi

exit "$failed"
