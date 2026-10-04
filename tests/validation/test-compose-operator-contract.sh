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
# The wrapper reads auth.type from the scope file to decide which credential
# to require, so the scope file can no longer be empty.
cat > "${tmp}/scope.yml" <<'EOF'
apiVersion: runsecure.io/v1alpha1
name: pat-scope
auth:
  type: pat
  pat_file: /run/secrets/runsecure-pat
EOF
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

# Raw `docker compose` is driven directly in the block below, so it needs the
# generic variables the wrapper would normally compute from auth.type.
export RUNSECURE_AUTH_SECRET_FILE="${tmp}/pat"
export RUNSECURE_AUTH_SECRET_NAME=runsecure-pat

if env -u RUNSECURE_AUTH_SECRET_HOST_VALIDATED docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-validation.out" 2>"${tmp}/missing-validation.err"; then
  echo "FAIL: raw Compose accepted a missing host auth-secret validation sentinel" >&2
  exit 1
fi
grep -q 'launch with infra/scripts/orchestrator-compose.sh' \
  "${tmp}/missing-validation.err"
export RUNSECURE_AUTH_SECRET_HOST_VALIDATED=runsecure-host-auth-secret-v1

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

if env -u RUNSECURE_AUTH_SECRET_FILE docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-secret.out" 2>"${tmp}/missing-secret.err"; then
  echo "FAIL: Compose accepted a missing RUNSECURE_AUTH_SECRET_FILE" >&2
  exit 1
fi
grep -q 'RUNSECURE_AUTH_SECRET_FILE is required' "${tmp}/missing-secret.err"

if env -u RUNSECURE_AUTH_SECRET_NAME docker compose -f "$COMPOSE_FILE" config \
    >"${tmp}/missing-name.out" 2>"${tmp}/missing-name.err"; then
  echo "FAIL: Compose accepted a missing RUNSECURE_AUTH_SECRET_NAME" >&2
  exit 1
fi
grep -q 'RUNSECURE_AUTH_SECRET_NAME is required' "${tmp}/missing-name.err"

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
auth_secret_init = rendered["services"]["auth-secret-init"]

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

init_mounts = {mount["target"]: mount for mount in auth_secret_init["volumes"]}
assert os.path.normpath(init_mounts["/host-auth-secret"]["source"]) == pat_source
assert init_mounts["/host-auth-secret"]["read_only"] is True
assert init_mounts["/secret"]["type"] == "volume"
assert auth_secret_init["read_only"] is True
assert "ALL" in auth_secret_init["cap_drop"]
assert set(auth_secret_init["cap_add"]) == {"CHOWN", "DAC_OVERRIDE"}
assert auth_secret_init["environment"]["RUNSECURE_AUTH_SECRET_HOST_VALIDATED"] == (
    "runsecure-host-auth-secret-v1"
)
assert auth_secret_init["environment"]["RUNSECURE_AUTH_SECRET_NAME"] == "runsecure-pat"
init_script = auth_secret_init["entrypoint"][2]
assert "[ -f /host-auth-secret ] && [ ! -L /host-auth-secret ]" in init_script
assert "stat -c '%a' /host-auth-secret" in init_script
assert init_script.index('rm -f "$$staged"') < init_script.index(
    'cp /host-auth-secret "$$staged"'
)
assert init_script.index('chmod 400 "$$staged"') < init_script.index(
    'chown 65532:65532 "$$staged"'
)
assert 'mv -f "$$staged" "$$target"' in init_script
assert "FOWNER" not in auth_secret_init["cap_add"]
assert orchestrator["depends_on"]["auth-secret-init"]["condition"] == "service_completed_successfully"

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
grep -q 'auth secret source must not be a symlink' "${tmp}/symlink.err"

# --- issue #64: a github_app scope must launch with NO PAT present ----------
# Before this, compose.scope.yml unconditionally required RUNSECURE_PAT_FILE
# and always ran a PAT init, so a valid app-auth scope could not start through
# the supported wrapper without also supplying an unrelated PAT.
cat > "${tmp}/app-scope.yml" <<'EOF'
apiVersion: runsecure.io/v1alpha1
name: app-scope
auth:
  type: github_app
  app_id: 123456
  installation_id: 7890123
  private_key_file: /run/secrets/runsecure-app-private-key
EOF
printf -- '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n' \
  > "${tmp}/app-key.pem"
chmod 0400 "${tmp}/app-key.pem"

app_env="${tmp}/app.env"
cat > "$app_env" <<EOF
COMPOSE_PROJECT_NAME=runsecure-app-validation-$$
RUNSECURE_SCOPE=app-validation-$$
RUNSECURE_SCOPE_FILE_HOST=${tmp}/app-scope.yml
RUNSECURE_PROJECTS_ROOT=$RUNSECURE_PROJECTS_ROOT
RUNSECURE_APP_PRIVATE_KEY_FILE=${tmp}/app-key.pem
RUNSECURE_ORCHESTRATOR_IMAGE=$RUNSECURE_ORCHESTRATOR_IMAGE
RUNSECURE_SOCKET_PROXY_IMAGE=$RUNSECURE_SOCKET_PROXY_IMAGE
RUNSECURE_PROXY_IMAGE=$RUNSECURE_PROXY_IMAGE
RUNSECURE_RUNNER_IMAGE_DEFAULT=$RUNSECURE_RUNNER_IMAGE_DEFAULT
EOF

# Scrub every PAT-related variable from the environment so this proves the
# app path needs no PAT at all, rather than inheriting one from above.
env -u RUNSECURE_PAT_FILE \
    -u RUNSECURE_AUTH_SECRET_FILE \
    -u RUNSECURE_AUTH_SECRET_NAME \
    -u RUNSECURE_AUTH_SECRET_HOST_VALIDATED \
    -u RUNSECURE_SCOPE_FILE_HOST \
    "$COMPOSE_WRAPPER" --env-file "$app_env" config --format json \
    >"${tmp}/app-rendered.json"

python3 - "${tmp}/app-rendered.json" "${tmp}/app-key.pem" <<'PY'
import json
import os
import pathlib
import sys

rendered = json.loads(pathlib.Path(sys.argv[1]).read_text())
key_source = os.path.abspath(sys.argv[2])
init = rendered["services"]["auth-secret-init"]
mounts = {mount["target"]: mount for mount in init["volumes"]}

# The App key is bound, not a PAT, and the in-volume name matches what the
# scope's private_key_file points at.
assert os.path.normpath(mounts["/host-auth-secret"]["source"]) == key_source
assert mounts["/host-auth-secret"]["read_only"] is True
assert init["environment"]["RUNSECURE_AUTH_SECRET_NAME"] == "runsecure-app-private-key"

# Nothing in the rendered config may reference a PAT path for an app scope.
blob = json.dumps(rendered)
assert "runsecure-pat" not in blob, "app scope still references a PAT secret"
PY

# A github_app scope with no private key must fail closed, naming the right
# variable rather than asking for a PAT.
sed '/RUNSECURE_APP_PRIVATE_KEY_FILE/d' "$app_env" > "${tmp}/app-nokey.env"
if env -u RUNSECURE_PAT_FILE -u RUNSECURE_APP_PRIVATE_KEY_FILE \
      -u RUNSECURE_SCOPE_FILE_HOST \
      "$COMPOSE_WRAPPER" --env-file "${tmp}/app-nokey.env" config \
      >"${tmp}/app-nokey.out" 2>"${tmp}/app-nokey.err"; then
  echo "FAIL: wrapper accepted a github_app scope with no private key" >&2
  exit 1
fi
grep -q 'RUNSECURE_APP_PRIVATE_KEY_FILE is required' "${tmp}/app-nokey.err"

# A mode-0644 private key must be rejected exactly like a mode-0644 PAT.
chmod 0644 "${tmp}/app-key.pem"
if env -u RUNSECURE_PAT_FILE -u RUNSECURE_SCOPE_FILE_HOST \
      "$COMPOSE_WRAPPER" --env-file "$app_env" config \
      >"${tmp}/app-mode.out" 2>"${tmp}/app-mode.err"; then
  echo "FAIL: wrapper accepted a mode-0644 App private key" >&2
  exit 1
fi
grep -q 'must be mode 0400 (got 0644)' "${tmp}/app-mode.err"
chmod 0400 "${tmp}/app-key.pem"

# An unknown auth.type must fail closed instead of silently defaulting to PAT.
sed 's/type: github_app/type: oauth_device/' "${tmp}/app-scope.yml" \
  > "${tmp}/bad-scope.yml"
sed "s#${tmp}/app-scope.yml#${tmp}/bad-scope.yml#" "$app_env" > "${tmp}/bad.env"
if env -u RUNSECURE_PAT_FILE -u RUNSECURE_SCOPE_FILE_HOST \
      "$COMPOSE_WRAPPER" --env-file "${tmp}/bad.env" config \
      >"${tmp}/bad.out" 2>"${tmp}/bad.err"; then
  echo "FAIL: wrapper accepted an unknown auth.type" >&2
  exit 1
fi
grep -q "auth.type must be 'pat' or 'github_app'" "${tmp}/bad.err"

if docker info >/dev/null 2>&1; then
  run_auth_secret_init() {
    "$COMPOSE_WRAPPER" --env-file "$operator_env" \
      up --no-deps --force-recreate --abort-on-container-exit \
      --exit-code-from auth-secret-init auth-secret-init >/dev/null
  }

  assert_secret() {
    local expected=$1
    docker run --rm \
      -v "${RUNSECURE_SCOPE}-auth-secret:/secret:ro" \
      alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 \
      sh -euc \
      'test -f /secret/runsecure-pat
       test ! -L /secret/runsecure-pat
       test "$(stat -c "%a:%u:%g" /secret/runsecure-pat)" = "400:65532:65532"
       test "$(cat /secret/runsecure-pat)" = "$1"' \
      sh "$expected"
  }

  run_auth_secret_init
  assert_secret first-test-token

  chmod 0600 "${tmp}/pat"
  printf 'second-test-token\n' > "${tmp}/pat"
  chmod 0400 "${tmp}/pat"
  run_auth_secret_init
  assert_secret second-test-token
else
  echo "SKIP: Docker daemon unavailable; auth-secret-init restart exercise not run"
fi

echo "PASS: Compose validates PAT and GitHub App credentials, restarts auth-secret-init, and preserves operator isolation"
