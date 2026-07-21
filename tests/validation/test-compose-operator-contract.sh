#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${RUNSECURE_ROOT}/infra/orchestrator/compose.scope.yml"
COMPOSE_WRAPPER="${RUNSECURE_ROOT}/infra/scripts/orchestrator-compose.sh"
INSTALL_GUIDE="${RUNSECURE_ROOT}/install.md"
ORCHESTRATOR_GUIDE="${RUNSECURE_ROOT}/infra/orchestrator/README.md"

python3 - "$INSTALL_GUIDE" "$ORCHESTRATOR_GUIDE" <<'PY'
import pathlib
import re
import sys

required_refs = {
    "SOCKET_PROXY_REF": "socket-proxy",
    "ORCHESTRATOR_REF": "orchestrator",
    "PROXY_REF": "proxy",
    "RUNNER_REF": "node-24",
}
env_refs = {
    "RUNSECURE_SOCKET_PROXY_IMAGE": "SOCKET_PROXY_REF",
    "RUNSECURE_ORCHESTRATOR_IMAGE": "ORCHESTRATOR_REF",
    "RUNSECURE_PROXY_IMAGE": "PROXY_REF",
    "RUNSECURE_RUNNER_IMAGE_DEFAULT": "RUNNER_REF",
}

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    text = path.read_text()
    assert 'runsecure-v${RUNSECURE_RELEASE}-release-images.json' in text, path
    assert "verify-release-manifest.py" in text, path
    for variable, key in required_refs.items():
        selector = f'{variable}=$(jq -er \'.images["{key}"]\' "$RUNSECURE_RELEASE_MANIFEST")'
        assert selector in text, (path, selector)
    for variable, reference in env_refs.items():
        assert f"{variable}=${reference}" in text, (path, variable)

    for line in text.splitlines():
        if re.match(r"RUNSECURE_(?:SOCKET_PROXY|ORCHESTRATOR|PROXY)_IMAGE=", line) \
                or line.startswith("RUNSECURE_RUNNER_IMAGE_DEFAULT="):
            assert ":latest" not in line and ":local" not in line, (path, line)

    assert "same release" in text.lower(), path
    assert "RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE_HOST" in text, path
PY

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: Docker Compose is unavailable"
  exit 0
fi

# Keep live bind sources below the checkout: Colima shares /Users with its VM,
# while the host's private TMPDIR is not visible to the Docker daemon and is
# therefore materialized as an empty directory rather than the intended file.
mkdir -p "${RUNSECURE_ROOT}/tmp"
tmp=$(mktemp -d "${RUNSECURE_ROOT}/tmp/runsecure-compose-test.XXXXXX")
operator_env="${tmp}/operator.env"
cleanup() {
  if [[ -f "$operator_env" ]]; then
    "$COMPOSE_WRAPPER" --env-file "$operator_env" down --volumes --remove-orphans \
      >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
touch "${tmp}/scope.yml"
printf 'first-test-token\n' > "${tmp}/pat"
chmod 0400 "${tmp}/pat"
mkdir "${tmp}/projects"

export RUNSECURE_SCOPE="pat-validation-$$"
export RUNSECURE_SCOPE_FILE_HOST="${tmp}/scope.yml"
export RUNSECURE_PROJECTS_ROOT="${tmp}/projects"
export RUNSECURE_PAT_FILE="${tmp}/pat"
export RUNSECURE_ORCHESTRATOR_IMAGE=example.invalid/runsecure/orchestrator:test
export RUNSECURE_SOCKET_PROXY_IMAGE=example.invalid/runsecure/socket-proxy:test
export RUNSECURE_PROXY_IMAGE=example.invalid/runsecure/proxy:test
export RUNSECURE_RUNNER_IMAGE_DEFAULT=example.invalid/runsecure/python:test

if env -u RUNSECURE_PAT_HOST_VALIDATED docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-validation.out" 2>"${tmp}/missing-validation.err"; then
  echo "FAIL: raw Compose accepted a missing host PAT validation sentinel" >&2
  exit 1
fi
grep -q 'launch with infra/scripts/orchestrator-compose.sh' \
  "${tmp}/missing-validation.err"
export RUNSECURE_PAT_HOST_VALIDATED=runsecure-host-pat-v1

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
assert pat_init["environment"]["RUNSECURE_PAT_HOST_VALIDATED"] == (
    "runsecure-host-pat-v1"
)
pat_init_script = pat_init["entrypoint"][2]
assert "[ -f /host-pat ] && [ ! -L /host-pat ]" in pat_init_script
assert "stat -c '%a' /host-pat" in pat_init_script
assert pat_init_script.index('rm -f "$$staged"') < pat_init_script.index(
    'cp /host-pat "$$staged"'
)
assert pat_init_script.index('chmod 400 "$$staged"') < pat_init_script.index(
    'chown 65532:65532 "$$staged"'
)
assert 'mv -f "$$staged" "$$target"' in pat_init_script
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

cat > "$operator_env" <<EOF
COMPOSE_PROJECT_NAME=runsecure-pat-validation-$$
RUNSECURE_SCOPE=$RUNSECURE_SCOPE
RUNSECURE_SCOPE_FILE_HOST=$RUNSECURE_SCOPE_FILE_HOST
RUNSECURE_PROJECTS_ROOT=$RUNSECURE_PROJECTS_ROOT
RUNSECURE_PAT_FILE=$RUNSECURE_PAT_FILE
RUNSECURE_ORCHESTRATOR_IMAGE=$RUNSECURE_ORCHESTRATOR_IMAGE
RUNSECURE_SOCKET_PROXY_IMAGE=$RUNSECURE_SOCKET_PROXY_IMAGE
RUNSECURE_PROXY_IMAGE=$RUNSECURE_PROXY_IMAGE
RUNSECURE_RUNNER_IMAGE_DEFAULT=$RUNSECURE_RUNNER_IMAGE_DEFAULT
EOF

"$COMPOSE_WRAPPER" --env-file "$operator_env" config --format json \
  >"${tmp}/wrapper-valid.json"

chmod 0644 "${tmp}/pat"
if "$COMPOSE_WRAPPER" --env-file "$operator_env" config \
    >"${tmp}/mode-0644.out" 2>"${tmp}/mode-0644.err"; then
  echo "FAIL: Compose wrapper accepted a mode-0644 PAT" >&2
  exit 1
fi
grep -q 'must be mode 0400 (got 0644)' "${tmp}/mode-0644.err"
chmod 0400 "${tmp}/pat"

ln -s "${tmp}/pat" "${tmp}/pat-link"
if RUNSECURE_PAT_FILE="${tmp}/pat-link" \
    "$COMPOSE_WRAPPER" --env-file "$operator_env" config \
    >"${tmp}/symlink.out" 2>"${tmp}/symlink.err"; then
  echo "FAIL: Compose wrapper accepted a symlink PAT" >&2
  exit 1
fi
grep -q 'PAT source must not be a symlink' "${tmp}/symlink.err"

if docker info >/dev/null 2>&1; then
  run_pat_init() {
    "$COMPOSE_WRAPPER" --env-file "$operator_env" \
      up --no-deps --force-recreate --abort-on-container-exit \
      --exit-code-from pat-init pat-init >/dev/null
  }

  assert_secret() {
    local expected=$1
    docker run --rm \
      -v "${RUNSECURE_SCOPE}-pat-secret:/secret:ro" \
      alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 \
      sh -euc \
      'test -f /secret/runsecure-pat
       test ! -L /secret/runsecure-pat
       test "$(stat -c "%a:%u:%g" /secret/runsecure-pat)" = "400:65532:65532"
       test "$(cat /secret/runsecure-pat)" = "$1"' \
      sh "$expected"
  }

  run_pat_init
  assert_secret first-test-token

  chmod 0600 "${tmp}/pat"
  printf 'second-test-token\n' > "${tmp}/pat"
  chmod 0400 "${tmp}/pat"
  run_pat_init
  assert_secret second-test-token
else
  echo "SKIP: Docker daemon unavailable; pat-init restart exercise not run"
fi

echo "PASS: Compose validates host PATs, restarts pat-init, and preserves operator isolation"
