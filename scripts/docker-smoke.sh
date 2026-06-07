#!/usr/bin/env bash
# Smoke-test the Docker Compose stack in a local-only configuration.
#
# This script is intentionally boring and self-contained: it builds the Compose
# stack, starts it detached under an isolated project name, waits for /api/health,
# captures logs on failure, and always tears containers down on exit.

set -Eeuo pipefail

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-odysseus_smoke}"
APP_BIND="${APP_BIND:-127.0.0.1}"
APP_PORT="${APP_PORT:-7000}"
AUTH_ENABLED="${AUTH_ENABLED:-true}"
LOCALHOST_BYPASS="${LOCALHOST_BYPASS:-false}"
ODYSSEUS_DEPLOYMENT_MODE="${ODYSSEUS_DEPLOYMENT_MODE:-local}"
ODYSSEUS_SETUP_TOKEN="${ODYSSEUS_SETUP_TOKEN:-docker-smoke-local-setup-token}"
DOCKER_SMOKE_LOG="${DOCKER_SMOKE_LOG:-docker-smoke.log}"
DOCKER_SMOKE_TIMEOUT_SECONDS="${DOCKER_SMOKE_TIMEOUT_SECONDS:-120}"
DOCKER_SMOKE_POLL_SECONDS="${DOCKER_SMOKE_POLL_SECONDS:-2}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:${APP_PORT}/api/health}"

export COMPOSE_PROJECT_NAME
export APP_BIND
export APP_PORT
export AUTH_ENABLED
export LOCALHOST_BYPASS
export ODYSSEUS_DEPLOYMENT_MODE
export ODYSSEUS_SETUP_TOKEN

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_BIN=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_BIN=(docker-compose)
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
  exit 127
fi

compose() {
  "${COMPOSE_BIN[@]}" -p "${COMPOSE_PROJECT_NAME}" "$@"
}

write_failure_log() {
  {
    echo "# Odysseus Docker smoke failure log"
    echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "compose_project=${COMPOSE_PROJECT_NAME}"
    echo "health_url=${HEALTH_URL}"
    echo
    echo "## docker compose ps"
    compose ps || true
    echo
    echo "## docker compose logs"
    compose logs --no-color --timestamps || true
  } >"${DOCKER_SMOKE_LOG}"

  echo "wrote ${DOCKER_SMOKE_LOG}" >&2
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    write_failure_log || true
  fi

  # Remove volumes as well as containers so a failed smoke run does not poison a
  # later run with partially-initialized SQLite state.
  compose down --remove-orphans -v >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

health_check() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 5 "${HEALTH_URL}" >/dev/null
    return $?
  fi

  python3 - "${HEALTH_URL}" <<'EOPY'
from __future__ import annotations

import sys
from urllib.request import urlopen

url = sys.argv[1]
with urlopen(url, timeout=5) as response:
    if response.status >= 400:
        raise SystemExit(1)
EOPY
}

echo "Building Docker Compose stack for project ${COMPOSE_PROJECT_NAME}..."
compose build

echo "Starting Docker Compose stack..."
compose up -d

echo "Waiting for ${HEALTH_URL}..."
deadline=$((SECONDS + DOCKER_SMOKE_TIMEOUT_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  if health_check; then
    echo "Docker smoke test passed: ${HEALTH_URL} is healthy."
    exit 0
  fi
  sleep "${DOCKER_SMOKE_POLL_SECONDS}"
done

echo "error: Docker smoke test timed out waiting for ${HEALTH_URL}" >&2
exit 1
