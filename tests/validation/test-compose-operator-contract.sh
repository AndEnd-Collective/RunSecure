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

env -u RUNSECURE_ORCHESTRATOR_HEALTH_PORT \
    -u RUNSECURE_ORCHESTRATOR_STATE_PORT \
    docker compose -f "$COMPOSE_FILE" config --format json > "${tmp}/rendered.json"
RUNSECURE_ORCHESTRATOR_HEALTH_PORT=18080 \
RUNSECURE_ORCHESTRATOR_STATE_PORT=18081 \
    docker compose -f "$COMPOSE_FILE" config --format json > "${tmp}/custom-ports.json"
python3 - \
    "${tmp}/rendered.json" \
    "${tmp}/custom-ports.json" \
    "${tmp}/scope.yml" \
    "${tmp}/projects" \
    "${tmp}/pat" <<'PY'
import json
import os
import pathlib
import sys

rendered = json.loads(pathlib.Path(sys.argv[1]).read_text())
custom_ports = json.loads(pathlib.Path(sys.argv[2]).read_text())
scope_source = os.path.abspath(sys.argv[3])
projects_source = os.path.abspath(sys.argv[4])
pat_source = os.path.abspath(sys.argv[5])
orchestrator = rendered["services"]["orchestrator"]
operator_relay = rendered["services"]["operator-relay"]
socket_proxy = rendered["services"]["socket-proxy"]
pat_init = rendered["services"]["pat-init"]

assert orchestrator["stop_grace_period"] == "1m30s"
assert str(orchestrator["environment"]["RUNSECURE_DRAIN_SECONDS"]) == "60"
assert set(orchestrator["networks"]) == {"orch-internal", "operator-internal"}
assert set(socket_proxy["networks"]) == {"orch-internal"}
assert "ports" not in orchestrator

assert set(operator_relay["networks"]) == {"operator-internal", "operator-host"}
assert operator_relay["image"] == "example.invalid/runsecure/proxy:test"
assert operator_relay["read_only"] is True
assert operator_relay["user"] == "1001:1001"
assert "ALL" in operator_relay["cap_drop"]
assert "no-new-privileges:true" in operator_relay["security_opt"]
assert operator_relay["depends_on"]["orchestrator"]["condition"] == "service_started"

relay_mounts = {mount["target"]: mount for mount in operator_relay["volumes"]}
assert set(relay_mounts) == {"/etc/runsecure/operator-relay.haproxy.cfg"}
assert relay_mounts["/etc/runsecure/operator-relay.haproxy.cfg"]["read_only"] is True

operator_network = rendered["networks"]["operator-host"]
assert operator_network["driver"] == "bridge"
assert operator_network.get("internal", False) is False
assert operator_network["driver_opts"] == {
    "com.docker.network.bridge.enable_ip_masquerade": "false",
    "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
}
assert rendered["networks"]["operator-internal"]["internal"] is True

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
pat_init_script = pat_init["entrypoint"][2]
assert pat_init_script.index("chmod 400 /secret/runsecure-pat") < pat_init_script.index(
    "chown 65532:65532 /secret/runsecure-pat"
)
assert "FOWNER" not in pat_init["cap_add"]
assert orchestrator["depends_on"]["pat-init"]["condition"] == "service_completed_successfully"

def assert_loopback_ports(config: dict, expected: dict[int, str]) -> None:
    ports = config["services"]["operator-relay"]["ports"]
    by_target = {int(port["target"]): port for port in ports}
    assert set(by_target) == set(expected)
    for target, published in expected.items():
        port = by_target[target]
        assert port["host_ip"] == "127.0.0.1"
        assert str(port["published"]) == published
        assert port["protocol"] == "tcp"


assert_loopback_ports(rendered, {8080: "8080", 8081: "8081"})
assert_loopback_ports(custom_ports, {8080: "18080", 8081: "18081"})

socket_mounts = {mount["target"]: mount for mount in socket_proxy["volumes"]}
assert socket_mounts["/run/secrets/extra-images.txt"]["source"] == "/dev/null"
assert socket_mounts["/run/secrets/extra-images.txt"]["read_only"] is True
PY

echo "PASS: Compose preserves portable inputs, loopback probes, and graceful shutdown"
