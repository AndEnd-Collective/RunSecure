#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${RUNSECURE_ROOT}/infra/orchestrator/compose.scope.yml"

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: Docker Compose is unavailable"
  exit 0
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-compose-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
touch "${tmp}/scope.yml" "${tmp}/pat"
mkdir "${tmp}/projects"

export RUNSECURE_SCOPE=validation
export RUNSECURE_SCOPE_FILE_HOST="${tmp}/scope.yml"
export RUNSECURE_PROJECTS_ROOT="${tmp}/projects"
export RUNSECURE_PAT_FILE="${tmp}/pat"
export RUNSECURE_ORCHESTRATOR_IMAGE=example.invalid/runsecure/orchestrator:test
export RUNSECURE_SOCKET_PROXY_IMAGE=example.invalid/runsecure/socket-proxy:test
export RUNSECURE_PROXY_IMAGE=example.invalid/runsecure/proxy:test
export RUNSECURE_RUNNER_IMAGE_DEFAULT=example.invalid/runsecure/python:test

if env -u RUNSECURE_SCOPE_FILE_HOST docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-scope.out" 2>"${tmp}/missing-scope.err"; then
  echo "FAIL: Compose accepted a missing RUNSECURE_SCOPE_FILE_HOST" >&2
  exit 1
fi
grep -q 'RUNSECURE_SCOPE_FILE_HOST is required' "${tmp}/missing-scope.err"

if env -u RUNSECURE_PROJECTS_ROOT docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-projects.out" 2>"${tmp}/missing-projects.err"; then
  echo "FAIL: Compose accepted a missing RUNSECURE_PROJECTS_ROOT" >&2
  exit 1
fi
grep -q 'RUNSECURE_PROJECTS_ROOT is required' "${tmp}/missing-projects.err"

if env -u RUNSECURE_PAT_FILE docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-pat.out" 2>"${tmp}/missing-pat.err"; then
  echo "FAIL: Compose accepted a missing RUNSECURE_PAT_FILE" >&2
  exit 1
fi
grep -q 'RUNSECURE_PAT_FILE is required' "${tmp}/missing-pat.err"

docker compose -f "$COMPOSE_FILE" config --format json > "${tmp}/rendered.json"
python3 - "${tmp}/rendered.json" "${tmp}/scope.yml" "${tmp}/projects" "${tmp}/pat" <<'PY'
import json
import os
import pathlib
import sys

rendered = json.loads(pathlib.Path(sys.argv[1]).read_text())
scope_source = os.path.abspath(sys.argv[2])
projects_source = os.path.abspath(sys.argv[3])
pat_source = os.path.abspath(sys.argv[4])
orchestrator = rendered["services"]["orchestrator"]
socket_proxy = rendered["services"]["socket-proxy"]
pat_init = rendered["services"]["pat-init"]

assert orchestrator["stop_grace_period"] == "1m30s"
assert str(orchestrator["environment"]["RUNSECURE_DRAIN_SECONDS"]) == "60"

mounts = {mount["target"]: mount for mount in orchestrator["volumes"]}
assert os.path.normpath(mounts["/etc/runsecure/scope.yml"]["source"]) == scope_source
assert mounts["/etc/runsecure/scope.yml"]["read_only"] is True
assert os.path.normpath(mounts["/projects"]["source"]) == projects_source
assert mounts["/projects"]["read_only"] is True
assert mounts["/run/secrets"]["type"] == "volume"
assert mounts["/run/secrets"]["read_only"] is True

pat_mounts = {mount["target"]: mount for mount in pat_init["volumes"]}
assert os.path.normpath(pat_mounts["/host-pat"]["source"]) == pat_source
assert pat_mounts["/host-pat"]["read_only"] is True
assert pat_mounts["/secret"]["type"] == "volume"
assert pat_init["read_only"] is True
assert "ALL" in pat_init["cap_drop"]
assert set(pat_init["cap_add"]) == {"CHOWN", "DAC_OVERRIDE"}
assert orchestrator["depends_on"]["pat-init"]["condition"] == "service_completed_successfully"

socket_mounts = {mount["target"]: mount for mount in socket_proxy["volumes"]}
assert socket_mounts["/run/secrets/extra-images.txt"]["source"] == "/dev/null"
assert socket_mounts["/run/secrets/extra-images.txt"]["read_only"] is True
PY

echo "PASS: Compose requires portable operator inputs and preserves graceful shutdown"
