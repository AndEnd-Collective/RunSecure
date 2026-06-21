#!/usr/bin/env bash
# Shared library for orchestrator-compose integration tests.
# Source from each test script; provides setup/teardown helpers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.test.yml"
TESTDATA_DIR="${SCRIPT_DIR}/testdata"

# Local registry used to produce TRUE manifest digests for locally-built images.
# On native-Linux CI, locally-built images have empty RepoDigests; docker create
# with @sha256:<config-id> fails because the daemon treats config IDs as manifest
# digests only for registry-pushed images. Pushing to a local registry:2 instance
# populates RepoDigests with a real manifest digest that any Docker engine resolves.
LOCAL_REGISTRY_HOST="localhost:5000"
LOCAL_REGISTRY_CONTAINER="rs-test-registry"

# Detect docker-compose v1 or v2 (plugin). Mirrors the dispatch pattern
# already used in infra/scripts/run.sh.
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "FATAL: neither 'docker compose' nor 'docker-compose' is installed" >&2
  exit 1
fi

# start_local_registry starts a registry:2 container on localhost:5000 if one
# is not already running. Idempotent: safe to call multiple times.
# The registry is only reachable from the HOST (127.0.0.1:5000), which is all
# that is needed — image resolution happens on the host Docker daemon.
start_local_registry() {
  # Already running — nothing to do.
  if docker ps --filter "name=${LOCAL_REGISTRY_CONTAINER}" --format '{{.Names}}' \
      | grep -q "^${LOCAL_REGISTRY_CONTAINER}$"; then
    return 0
  fi
  # Remove any stopped container with this name from a previous aborted run.
  docker rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
  docker run -d \
    --name "${LOCAL_REGISTRY_CONTAINER}" \
    -p "127.0.0.1:5000:5000" \
    --label "runsecure.scope=test" \
    registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 \
    >/dev/null
  # Wait for the registry to become ready.  registry:2 typically starts in
  # under one second; 30 s timeout is generous for a slow CI host.
  local elapsed=0
  while (( elapsed < 30 )); do
    # A manifest-not-found error from the registry proves the HTTP server is up.
    # The '|| true' prevents set -e from aborting on the non-zero exit of docker pull.
    local probe_out
    probe_out=$(docker pull "${LOCAL_REGISTRY_HOST}/runsecure-probe:nope" 2>&1) || true
    if echo "${probe_out}" | grep -qE "manifest unknown|not found|does not exist|repository.*not found"; then
      return 0
    fi
    sleep 1
    elapsed=$(( elapsed + 1 ))
  done
  echo "FATAL: local registry (${LOCAL_REGISTRY_CONTAINER}) never became ready" >&2
  return 1
}

# push_and_get_digest <local_tag> <registry_repo>
# Tags <local_tag> as ${LOCAL_REGISTRY_HOST}/<registry_repo>, pushes it, and
# prints the full digest ref (localhost:5000/<repo>@sha256:<manifest>) that the
# Docker daemon can resolve on any platform — including native-Linux CI where
# locally-built images have empty RepoDigests.
push_and_get_digest() {
  local local_tag="$1"
  local registry_repo="$2"
  local registry_ref="${LOCAL_REGISTRY_HOST}/${registry_repo}"

  docker tag "${local_tag}" "${registry_ref}"
  docker push "${registry_ref}" >/dev/null

  # After a successful push the daemon updates RepoDigests with the manifest
  # digest returned by the registry.  This is the TRUE manifest digest that
  # dockerd resolves when given a @sha256: ref — unlike .Id (config digest),
  # which only works on Colima/Docker Desktop by coincidence.
  local digest
  digest=$(docker image inspect "${registry_ref}" --format '{{index .RepoDigests 0}}')
  echo "${digest}"
}

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
  fi
  # Mode 0400: PAT is delivered to the orchestrator via the pat-secret named
  # volume (see pat-init in docker-compose.test.yml) rather than a direct host
  # bind-mount. The host file itself only needs to be readable by the current
  # user so the pat-init container can bind-mount and copy it; mode 0400 is
  # correct and matches the orchestrator's security requirement.
  chmod 400 "${TESTDATA_DIR}/pat"
  # The orchestrator (HEAD) attaches per-spawn proxy containers to the egress
  # network (RUNSECURE_EGRESS_NETWORK, default: runsecure-egress). Create it
  # here so the spawn path succeeds even in the bare test environment.
  docker network inspect runsecure-egress >/dev/null 2>&1 \
    || docker network create runsecure-egress >/dev/null
  # Bug #5 fix: generate a test allowed-images.txt so socket-proxy will
  # accept spawns of a real test-runner image.
  ensure_test_allowlist
}

# build_test_runner_image creates a minimal alpine-based image that the
# integration tests use in place of a real actions/runner. It exposes the
# networking tools we need to probe structural-floor properties from
# inside a spawned runner container.
build_test_runner_image() {
  if docker image inspect runsecure-test-runner:local >/dev/null 2>&1; then
    return 0
  fi
  local builddir
  builddir=$(mktemp -d)
  cat > "${builddir}/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl bind-tools iproute2 netcat-openbsd
USER 1001:0
ENTRYPOINT ["sleep", "120"]
EOF
  docker build -t runsecure-test-runner:local "$builddir" >/dev/null
  rm -rf "$builddir"
}

# ensure_test_allowlist resolves the TRUE manifest digest of the local
# test-runner image by pushing it to the local registry and reading back the
# populated RepoDigests field.  The resulting ref is written to allowed-images.txt
# and exported as RUNSECURE_TEST_RUNNER_REF.
#
# Why not use {{.Id}}?  On native-Linux CI the Docker daemon treats @sha256:
# refs as manifest digests (from a registry push), not image config digests.
# Locally-built images have empty RepoDigests, so docker create with
# @sha256:<config-id> fails with "No such image".  Pushing to a local
# registry:2 instance populates RepoDigests with a real manifest digest that
# resolves on every platform.
#
# If RUNSECURE_TEST_OVERRIDE_ALLOWLIST is set, the file is NOT overwritten
# (the caller has set up a deliberately-empty allowlist for the
# leak-cleanup test). The env-var export still happens so the orchestrator
# tries to spawn (and gets refused by the empty allowlist).
ensure_test_allowlist() {
  build_test_runner_image
  start_local_registry
  local ref
  ref=$(push_and_get_digest "runsecure-test-runner:local" "runsecure-test-runner")
  # RUNSECURE_TEST_OVERRIDE_ALLOWLIST: skip file write when the caller has
  # pre-populated the allowlist (e.g. ensure_egress_allowlist with both runner
  # and proxy refs) or deliberately set an empty list (leak-cleanup test).
  if [[ -z "${RUNSECURE_TEST_OVERRIDE_ALLOWLIST:-}" ]]; then
    cat > "${TESTDATA_DIR}/allowed-images.txt" <<EOF
# Test allowlist generated by _lib.sh (runner via local registry).
${ref}
EOF
  fi
  export RUNSECURE_TEST_RUNNER_REF="${ref}"
  # RUNSECURE_TEST_PROXY_REF: only override if it was not already set by
  # ensure_egress_allowlist (which sets it to the real proxy image digest).
  if [[ -z "${RUNSECURE_TEST_PROXY_REF:-}" ]]; then
    export RUNSECURE_TEST_PROXY_REF="${ref}"
  fi
}

# RUNSECURE_ROOT resolves to the repo root regardless of working directory.
RUNSECURE_ROOT="${SCRIPT_DIR}/../../../../"
RUNSECURE_ROOT="$(cd "${RUNSECURE_ROOT}" && pwd)"

# build_orchestrator_stack_images builds the runsecure-orchestrator:local and
# runsecure-socket-proxy:local images used by the compose test stack. Both are
# Go binaries in their own modules; the build is cached if already up-to-date.
build_orchestrator_stack_images() {
  docker build \
    -f "${RUNSECURE_ROOT}/infra/orchestrator/Dockerfile" \
    -t runsecure-orchestrator:local \
    "${RUNSECURE_ROOT}/infra/orchestrator" \
    >/dev/null
  docker build \
    -f "${RUNSECURE_ROOT}/infra/socket-proxy/Dockerfile" \
    -t runsecure-socket-proxy:local \
    "${RUNSECURE_ROOT}/infra/socket-proxy" \
    >/dev/null
}

# build_real_proxy_image builds the production runsecure-proxy image and tags
# it as runsecure-proxy:itest for use in egress integration tests.
build_real_proxy_image() {
  docker build \
    -f "${RUNSECURE_ROOT}/infra/squid/Dockerfile" \
    -t runsecure-proxy:itest \
    "${RUNSECURE_ROOT}/infra/squid" \
    >/dev/null
}

# ensure_egress_allowlist extends the allowed-images.txt with the real proxy
# image digest so socket-proxy accepts both runner and proxy spawns.
# Also rebuilds the orchestrator and socket-proxy stack images to ensure
# they reflect the current source (stale images cause spawn failures).
#
# Both images are pushed to the local registry so that their RepoDigests are
# populated with TRUE manifest digests. On native-Linux CI, locally-built
# images have empty RepoDigests; using {{.Id}} (config digest) in a @sha256:
# ref causes docker create to fail with "No such image" because the daemon
# only resolves config digests as @sha256: refs for registry-pushed images.
ensure_egress_allowlist() {
  build_orchestrator_stack_images
  build_real_proxy_image
  build_test_runner_image
  start_local_registry

  local proxy_ref runner_ref
  proxy_ref=$(push_and_get_digest "runsecure-proxy:itest" "runsecure-proxy")
  runner_ref=$(push_and_get_digest "runsecure-test-runner:local" "runsecure-test-runner")

  cat > "${TESTDATA_DIR}/allowed-images.txt" <<EOF
# Egress-test allowlist generated by _lib.sh (real proxy + test runner via local registry).
${runner_ref}
${proxy_ref}
EOF

  export RUNSECURE_TEST_RUNNER_REF="${runner_ref}"
  export RUNSECURE_TEST_PROXY_REF="${proxy_ref}"
  # Prevent ensure_test_allowlist (called via stack_up → ensure_testdata) from
  # overwriting the multi-image allowlist that this function just wrote.
  export RUNSECURE_TEST_OVERRIDE_ALLOWLIST=1
}

# write_egress_runner_yml writes a runner.yml with TCP+HTTP egress fields to
# testdata/proj/.github/runner.yml, backing up the original as runner.yml.orig.
write_egress_runner_yml() {
  local orig="${TESTDATA_DIR}/proj/.github/runner.yml"
  if [[ ! -f "${orig}.orig" && -f "${orig}" ]]; then
    cp "${orig}" "${orig}.orig"
  fi
  cat > "${orig}" <<'EOF'
runtime: node:24
labels: [self-hosted, Linux, container]
resources:
  memory: 4g
  cpus: 2
  pids: 1024
egress:
  allow_domains: [api.github.com]
http_egress: [api.github.com]
tcp_egress: [test-backend:5432]
orchestrator:
  timeout_seconds: 60
EOF
}

# restore_runner_yml restores the backed-up runner.yml.
restore_runner_yml() {
  local orig="${TESTDATA_DIR}/proj/.github/runner.yml"
  if [[ -f "${orig}.orig" ]]; then
    mv "${orig}.orig" "${orig}"
  fi
}

# start_test_backend starts a lightweight TCP+HTTP backend on the spawn-egress
# network, listening on port 5432 (TCP) and port 80 (HTTP). The container is
# labelled runsecure.scope=test so stack_down cleans it up.
start_test_backend() {
  # Ensure the spawn-egress network exists so test containers can join it.
  docker network inspect spawn-egress >/dev/null 2>&1 \
    || docker network create spawn-egress >/dev/null

  # Remove any leftover container from a previous aborted run.
  docker rm -f rs-test-backend >/dev/null 2>&1 || true

  # python:3-alpine: socat listens on TCP 5432 and echos; http.server on 80.
  # socat is installed via apk, then started in background; http.server runs
  # in foreground to keep the container alive.
  docker run -d \
    --name rs-test-backend \
    --network spawn-egress \
    --network-alias test-backend \
    --label runsecure.scope=test \
    python:3-alpine \
    sh -c 'apk add --no-cache socat >/dev/null 2>&1 && socat TCP-LISTEN:5432,fork,reuseaddr ECHO & python3 -m http.server 80' \
    >/dev/null
}

# generate_egress_configs writes squid.conf, haproxy.cfg, and dnsmasq.conf to
# a host-side directory that is accessible to the Docker daemon for bind mounts.
# This mirrors what the orchestrator does at spawn time (via egress.Render) but
# without requiring the orchestrator to write from its own container tmpfs.
#
# The generated squid.conf allows api.github.com; haproxy.cfg opens port 5432
# to test-backend:5432; dnsmasq.conf is a no-op placeholder.
generate_egress_configs() {
  local dir="${TESTDATA_DIR}/egress-itest"
  mkdir -p "${dir}"

  # squid.conf — allows api.github.com on 443 only; denies everything else.
  # Mirrors the output of egress.RenderSquid() for a runner with
  # http_egress: [api.github.com].
  cat > "${dir}/squid.conf" <<'EOF'
# RunSecure squid.conf — generated for egress integration test.
http_port 3128
acl allowed_domains dstdomain .api.github.com
acl CONNECT method CONNECT
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
http_access deny CONNECT !SSL_ports
http_access allow allowed_domains
http_access deny all
visible_hostname runsecure-proxy
access_log stdio:/var/log/squid/access.log
pid_filename /var/run/squid/squid.pid
cache deny all
forwarded_for delete
via off
dns_nameservers 8.8.8.8 8.8.4.4
EOF

  # haproxy.cfg — TCP frontend on :5432 forwarding to test-backend:5432.
  cat > "${dir}/haproxy.cfg" <<'EOF'
# RunSecure haproxy.cfg — generated for egress integration test.
global
  maxconn 256

defaults
  mode tcp
  timeout connect 10s
  timeout client 60s
  timeout server 60s

resolvers default_dns
  parse-resolv-conf
  resolve_retries 3
  timeout retry 1s
  hold valid 10s

frontend tcp_5432
  bind :5432
  default_backend backend_5432

backend backend_5432
  server srv_5432 test-backend:5432 check resolvers default_dns init-addr none
EOF

  # dnsmasq.conf — minimal placeholder; ENABLE_DNSMASQ=false so it is not started.
  cat > "${dir}/dnsmasq.conf" <<'EOF'
# RunSecure dnsmasq.conf — not used (ENABLE_DNSMASQ=false).
no-resolv
server=1.1.1.1
local=/./
EOF

  echo "${dir}"
}

# start_real_proxy starts the real runsecure-proxy:itest container with
# host-generated egress configs on two networks:
#   - rs-egress-internal: internal network shared with the test runner
#   - spawn-egress: external network for outbound internet access
# The container is labelled runsecure.scope=test so stack_down cleans it up.
#
# Globals set: REAL_PROXY_CONTAINER (container name), REAL_PROXY_NETWORK (internal net)
REAL_PROXY_CONTAINER="rs-egress-proxy"
REAL_PROXY_NETWORK="rs-egress-internal"

start_real_proxy() {
  local egress_dir
  egress_dir="$(generate_egress_configs)"

  # Internal network: runner ↔ proxy (no external access).
  docker network inspect "${REAL_PROXY_NETWORK}" >/dev/null 2>&1 \
    || docker network create --internal "${REAL_PROXY_NETWORK}" >/dev/null
  # Egress network: proxy ↔ internet (test-backend on this network).
  docker network inspect spawn-egress >/dev/null 2>&1 \
    || docker network create spawn-egress >/dev/null

  docker rm -f "${REAL_PROXY_CONTAINER}" >/dev/null 2>&1 || true

  # Start the real proxy with per-spawn configs from the HOST-side directory.
  # --network=rs-egress-internal --network-alias=proxy so the runner can reach
  # squid via http://proxy:3128 and haproxy via tcp proxy:5432.
  # tmpfs mounts mirror what the production spawn wires (ReadonlyRootfs+tmpfs):
  #   - /var/run/squid  — squid PID file
  #   - /var/log/squid  — squid access log (stdio: so not strictly needed, but safe)
  #   - /var/spool/squid — squid cache (cache deny all, but squid still accesses)
  #   - /var/lib/haproxy — haproxy stats socket
  docker run -d \
    --name "${REAL_PROXY_CONTAINER}" \
    --label "runsecure.scope=test" \
    --user 1001:1001 \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /var/run/squid:uid=1001,gid=1001,mode=750 \
    --tmpfs /var/log/squid:uid=1001,gid=1001,mode=750 \
    --tmpfs /var/spool/squid:uid=1001,gid=1001,mode=750 \
    --tmpfs /var/lib/haproxy:uid=1001,gid=1001,mode=750 \
    --tmpfs /run:uid=1001,gid=1001,mode=750 \
    --network "${REAL_PROXY_NETWORK}" \
    --network-alias proxy \
    -e ENABLE_HAPROXY=true \
    -v "${egress_dir}/squid.conf:/etc/squid/squid.conf:ro" \
    -v "${egress_dir}/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro" \
    -v "${egress_dir}/dnsmasq.conf:/etc/dnsmasq.conf:ro" \
    runsecure-proxy:itest \
    >/dev/null

  # Connect proxy to egress network so it can reach test-backend and the internet.
  docker network connect spawn-egress "${REAL_PROXY_CONTAINER}" >/dev/null 2>&1 || true
}

# start_real_runner starts the alpine test runner on the internal network.
# Prints the container ID.
start_real_runner() {
  docker rm -f rs-egress-runner >/dev/null 2>&1 || true
  docker run -d \
    --name rs-egress-runner \
    --label "runsecure.scope=test" \
    --user 1001:0 \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    --network "${REAL_PROXY_NETWORK}" \
    -e "HTTP_PROXY=http://proxy:3128" \
    -e "HTTPS_PROXY=http://proxy:3128" \
    -e "NO_PROXY=localhost" \
    runsecure-test-runner:local \
    >/dev/null
  docker ps --filter "name=rs-egress-runner" --format '{{.ID}}'
}

# setup_real_proxy_stack builds the proxy image, starts the backend, proxy, and
# runner containers. Sets EGRESS_RUNNER global.
EGRESS_RUNNER=""

setup_real_proxy_stack() {
  build_real_proxy_image
  build_test_runner_image
  start_test_backend
  start_real_proxy

  # Wait for squid to be ready (pid file appears).
  local elapsed=0
  while (( elapsed < 30 )); do
    if docker exec "${REAL_PROXY_CONTAINER}" \
        sh -c 'test -f /var/run/squid/squid.pid' >/dev/null 2>&1; then
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  if (( elapsed >= 30 )); then
    echo "WARN: squid may not be ready yet"
  fi

  EGRESS_RUNNER="$(start_real_runner)"
  echo "Egress runner: ${EGRESS_RUNNER}"
}

# teardown_real_proxy_stack stops and removes all test containers and networks.
teardown_real_proxy_stack() {
  docker rm -f "${REAL_PROXY_CONTAINER}" rs-egress-runner rs-test-backend >/dev/null 2>&1 || true
  docker rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${REAL_PROXY_NETWORK}" spawn-egress >/dev/null 2>&1 || true
  restore_runner_yml 2>/dev/null || true
  rm -rf "${TESTDATA_DIR}/egress-itest" 2>/dev/null || true
}

# stack_up_real_proxy is kept for backward compatibility but now delegates to
# setup_real_proxy_stack. Tests that need the orchestrator compose stack should
# use the orchestrator-compose test suite; tests that exercise the real proxy's
# egress filtering use setup_real_proxy_stack / teardown_real_proxy_stack.
stack_up_real_proxy() {
  mkdir -p "${TESTDATA_DIR}/proj/.github"
  setup_real_proxy_stack
}

# project_name returns a unique compose project name based on this script.
project_name() {
  echo "rs-test-$(basename "$0" .sh)"
}

stack_up() {
  local pname; pname="$(project_name)"
  ensure_testdata
  # The orchestrator + socket-proxy compose services reference local-only image
  # tags (runsecure-orchestrator:local, runsecure-socket-proxy:local) that have
  # no build context in the compose file, so `up --build` would try to PULL them
  # and fail on a fresh CI host. Build them here so EVERY suite using stack_up
  # has them (previously only ensure_egress_allowlist built them, so suites like
  # compose-egress-attach-deny pulled and failed). Idempotent / layer-cached.
  build_orchestrator_stack_images
  # egress-init and pat-init run first (service_completed_successfully
  # dependency) so the orchestrator starts with correct volume ownership.
  # Listing them explicitly forces compose to include them even though they
  # are not network-visible services.
  $DC -f "${COMPOSE_FILE}" -p "${pname}" up -d --build mock-github socket-proxy egress-init pat-init orchestrator
}

stack_down() {
  local pname; pname="$(project_name)"
  $DC -f "${COMPOSE_FILE}" -p "${pname}" down --volumes --remove-orphans 2>/dev/null || true
  # Spawn-sibling containers live OUTSIDE the compose project — reap by label.
  # This also removes the local registry (labelled runsecure.scope=test).
  docker ps -a --filter "label=runsecure.scope=test" --format '{{.ID}}' \
    | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network ls --filter "name=rs-net-" --format '{{.ID}}' \
    | xargs -r docker network rm >/dev/null 2>&1 || true
  # Clean up the shared egress network used by all spawn tests.
  docker network rm runsecure-egress >/dev/null 2>&1 || true
  # Remove real-proxy egress test containers and networks (setup_real_proxy_stack).
  teardown_real_proxy_stack 2>/dev/null || true
}

orch_logs() {
  local pname; pname="$(project_name)"
  $DC -f "${COMPOSE_FILE}" -p "${pname}" logs orchestrator 2>&1
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
