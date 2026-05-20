#!/usr/bin/env bash
# Shared library for orchestrator-compose integration tests.
# Source from each test script; provides setup/teardown helpers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.test.yml"
TESTDATA_DIR="${SCRIPT_DIR}/testdata"

ensure_testdata() {
  mkdir -p "${TESTDATA_DIR}/proj/.github"
  if [[ ! -f "${TESTDATA_DIR}/proj/.github/runner.yml" ]]; then
    cat > "${TESTDATA_DIR}/proj/.github/runner.yml" <<'EOF'
runtime: node:24
labels: [self-hosted, Linux, container]
resources:
  memory: 4g
  cpus: 2
  pids: 1024
egress:
  allow_domains: [api.github.com]
orchestrator:
  timeout_seconds: 60
EOF
  fi
  if [[ ! -f "${TESTDATA_DIR}/scope.yml" ]]; then
    cat > "${TESTDATA_DIR}/scope.yml" <<'EOF'
apiVersion: runsecure.io/v1alpha1
name: test
global_max_runners: 3
poll_interval_seconds: 5
security_profile: strict
auth:
  type: pat
  pat_file: /run/secrets/runsecure-pat
orch_egress:
  allow_domains: [api.github.com]
repos:
  - repo: owner/repo
    project_dir: /projects/proj
    max_concurrent: 2
EOF
  fi
  if [[ ! -f "${TESTDATA_DIR}/pat" ]]; then
    echo "ghp_fake_for_tests" > "${TESTDATA_DIR}/pat"
    chmod 400 "${TESTDATA_DIR}/pat"
  fi
}

# project_name returns a unique compose project name based on this script.
project_name() {
  echo "rs-test-$(basename "$0" .sh)"
}

stack_up() {
  local pname; pname="$(project_name)"
  ensure_testdata
  docker compose -f "${COMPOSE_FILE}" -p "${pname}" up -d --build mock-github socket-proxy orchestrator
}

stack_down() {
  local pname; pname="$(project_name)"
  docker compose -f "${COMPOSE_FILE}" -p "${pname}" down --volumes --remove-orphans 2>/dev/null || true
}

orch_logs() {
  local pname; pname="$(project_name)"
  docker compose -f "${COMPOSE_FILE}" -p "${pname}" logs orchestrator 2>&1
}

# wait_for_log <pattern> [timeout_seconds]
wait_for_log() {
  local pat="$1"; local timeout="${2:-30}"
  local elapsed=0
  while (( elapsed < timeout )); do
    if orch_logs | grep -q "${pat}"; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "wait_for_log: never saw pattern: ${pat}" >&2
  orch_logs | tail -50 >&2
  return 1
}
