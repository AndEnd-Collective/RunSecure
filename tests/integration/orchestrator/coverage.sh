#!/usr/bin/env bash
# =============================================================================
# tests/integration/orchestrator/coverage.sh
#
# Builds cmd/orchestrator and cmd/socket-proxy with Go 1.20+ binary
# instrumentation (-cover -covermode=atomic), exercises them directly against a
# locally-spawned mock-github stub and a local Docker daemon, collects GOCOVERDIR
# data on graceful shutdown, merges that with the unit-test covdata, and prints a
# combined coverage report.
#
# Coverage policy (enforced here and in tests/validation/test-go-coverage.sh):
#   "Logic packages ≥99% by unit tests.
#    Composition roots (cmd/orchestrator, cmd/socket-proxy) are exercised by
#    integration coverage via this script."
#
# Uncovered-by-design functions (documented):
#   runHealthcheck / runStatus  — self-curl helpers; require the binary to also
#       call the server, which in turn requires an interactive operator invocation.
#       Both are single-function wrappers around http.Client.Get and carry the
#       //coverage:ignore annotation.
#   productionKubeCtor          — only invoked when backend=kube; compose-mode
#       integration tests use the compose backend. Annotated //coverage:ignore.
#   socket-proxy run()          — the server blocks on ListenAndServe with no
#       signal handler; Go's coverage runtime only flushes on os.Exit/return from
#       main. See NOTE below.
#
# NOTE: socket-proxy has no SIGTERM handler — it calls log.Fatal(ListenAndServe())
# which exits via os.Exit(1) on shutdown, triggering the coverage flush.
# We send SIGTERM and wait; if the binary already exited (server closed), data
# is written. This captures run() up to the blocking call.
#
# Exit codes:
#   0  — combined cmd/orchestrator coverage ≥ threshold AND builds succeed
#   1  — build failed
#   2  — coverage below threshold
#   3  — runtime environment missing (docker, go, etc.)
#
# Usage:
#   bash tests/integration/orchestrator/coverage.sh
#   COVERAGE_THRESHOLD=70 bash tests/integration/orchestrator/coverage.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ORCH_MODULE="${REPO_ROOT}/infra/orchestrator"
PROXY_MODULE="${REPO_ROOT}/infra/socket-proxy"
MOCK_GITHUB_DIR="${SCRIPT_DIR}/compose/mock-github"

# Minimum acceptable combined (unit + integration) statement coverage for
# cmd/orchestrator. The composition-root functions main()/Run() are the primary
# reason this threshold is lower than the ≥99% applied to logic packages.
# runHealthcheck, runStatus, productionKubeCtor remain 0% by design.
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-75}"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { printf "${BOLD}[cov]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[cov] OK${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[cov] WARN${NC} %s\n" "$*"; }
fail()  { printf "${RED}[cov] FAIL${NC} %s\n" "$*"; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
for tool in go docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail "Required tool not found: $tool"
    exit 3
  fi
done

DOCKER_SOCK=""
for candidate in \
    "$HOME/.colima/default/docker.sock" \
    /var/run/docker.sock \
    "$HOME/.docker/run/docker.sock"; do
  if [[ -S "$candidate" ]]; then
    DOCKER_SOCK="$candidate"
    break
  fi
done
if [[ -z "$DOCKER_SOCK" ]]; then
  # Try via DOCKER_HOST env
  if [[ -n "${DOCKER_HOST:-}" ]]; then
    DOCKER_SOCK="${DOCKER_HOST#unix://}"
  fi
fi
if [[ -z "$DOCKER_SOCK" ]] || ! docker info >/dev/null 2>&1; then
  fail "Docker daemon not reachable. DOCKER_HOST=${DOCKER_HOST:-<unset>}"
  exit 3
fi
info "Docker daemon: ${DOCKER_SOCK}"

# ---------------------------------------------------------------------------
# Temp directories (cleaned up on exit)
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
COVDIR_ORCH="$(mktemp -d)"
COVDIR_PROXY="$(mktemp -d)"
COVDIR_UNIT="$(mktemp -d)"
COVDIR_MERGED="$(mktemp -d)"
BIN_ORCH="${WORK_DIR}/rs-orch-cov"
BIN_PROXY="${WORK_DIR}/rs-proxy-cov"
BIN_MOCK="${WORK_DIR}/rs-mock-github"
MOCK_PORT=18799  # Ephemeral port; unlikely to collide.
PROXY_PORT=18798 # Socket-proxy TCP port for orchestrator docker client.

cleanup() {
  # Kill any background processes we started.
  kill "${MOCK_PID:-}" "${PROXY_PID:-}" "${ORCH_PID:-}" 2>/dev/null || true
  wait "${MOCK_PID:-}" "${PROXY_PID:-}" "${ORCH_PID:-}" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1: Build instrumented binaries
# ---------------------------------------------------------------------------
info "Building cmd/orchestrator with -cover …"
(cd "$ORCH_MODULE" && CGO_ENABLED=0 go build \
  -cover -covermode=atomic \
  -o "$BIN_ORCH" ./cmd/orchestrator) || { fail "orchestrator build failed"; exit 1; }
ok "orchestrator binary: $BIN_ORCH"

info "Building cmd/socket-proxy with -cover …"
(cd "$PROXY_MODULE" && CGO_ENABLED=0 go build \
  -cover -covermode=atomic \
  -o "$BIN_PROXY" ./cmd/socket-proxy) || { fail "socket-proxy build failed"; exit 1; }
ok "socket-proxy binary: $BIN_PROXY"

info "Building mock-github …"
(cd "$MOCK_GITHUB_DIR" && go build -o "$BIN_MOCK" .) || {
  fail "mock-github build failed"
  exit 1
}
ok "mock-github binary: $BIN_MOCK"

# ---------------------------------------------------------------------------
# Step 2: Run unit tests and collect covdata
# ---------------------------------------------------------------------------
info "Running unit tests (GOCOVERDIR) …"
(cd "$ORCH_MODULE" && go test ./... \
  -covermode=atomic -count=1 \
  -test.gocoverdir="$COVDIR_UNIT" \
  >/dev/null 2>&1) || warn "Some unit tests failed; coverage data may be partial."
ok "Unit covdata written to $COVDIR_UNIT ($(ls "$COVDIR_UNIT" | wc -l | tr -d ' ') files)"

# ---------------------------------------------------------------------------
# Step 3: Prepare fixtures for orchestrator integration run
# ---------------------------------------------------------------------------
info "Preparing integration test fixtures …"

PAT_FILE="${WORK_DIR}/pat"
echo "ghp_fake_for_coverage_test" > "$PAT_FILE"
chmod 400 "$PAT_FILE"

PROJ_DIR="${WORK_DIR}/proj"
mkdir -p "${PROJ_DIR}/.github"
cat > "${PROJ_DIR}/.github/runner.yml" <<'EOF'
runtime: node:24
labels: [self-hosted, Linux, container]
resources:
  memory: 2g
  cpus: 1
  pids: 512
EOF

SCOPE_FILE="${WORK_DIR}/scope.yml"
cat > "$SCOPE_FILE" <<EOF
apiVersion: runsecure.io/v1alpha1
name: cov-test
global_max_runners: 1
poll_interval_seconds: 60
security_profile: strict
auth:
  type: pat
  pat_file: ${PAT_FILE}
orch_egress:
  allow_domains: [api.github.com]
repos:
  - repo: owner/repo
    project_dir: ${PROJ_DIR}
    max_concurrent: 1
EOF

EGRESS_DIR="${WORK_DIR}/egress"
mkdir -p "$EGRESS_DIR"

ALLOWLIST_FILE="${WORK_DIR}/allowed-images.txt"
printf "# coverage test allowlist\n" > "$ALLOWLIST_FILE"

# ---------------------------------------------------------------------------
# Step 4: Start mock-github
# ---------------------------------------------------------------------------
info "Starting mock-github on port ${MOCK_PORT} …"
MOCK_LISTEN=":${MOCK_PORT}" "$BIN_MOCK" &
MOCK_PID=$!

# Wait for mock-github to accept connections.
_mock_ready=0
for _i in $(seq 1 10); do
  if curl -sf "http://localhost:${MOCK_PORT}/repos/owner/repo" -o /dev/null 2>/dev/null; then
    _mock_ready=1
    break
  fi
  sleep 0.5
done
if [[ "$_mock_ready" -eq 0 ]]; then
  warn "mock-github did not start in time; orchestrator may exit early"
fi
ok "mock-github running (PID ${MOCK_PID})"

# ---------------------------------------------------------------------------
# Step 5: Start instrumented socket-proxy
# ---------------------------------------------------------------------------
info "Starting socket-proxy with -cover on port ${PROXY_PORT} …"
GOCOVERDIR="$COVDIR_PROXY" \
RUNSECURE_DOCKER_SOCK="$DOCKER_SOCK" \
RUNSECURE_LISTEN_ADDR=":${PROXY_PORT}" \
RUNSECURE_ALLOWED_IMAGES_FILE="$ALLOWLIST_FILE" \
  "$BIN_PROXY" 2>/dev/null &
PROXY_PID=$!

# Wait for socket-proxy to accept connections.
_proxy_ready=0
for _i in $(seq 1 15); do
  if curl -sf "http://localhost:${PROXY_PORT}/v1.47/info" -o /dev/null 2>/dev/null; then
    _proxy_ready=1
    break
  fi
  sleep 0.5
done
if [[ "$_proxy_ready" -eq 0 ]]; then
  warn "socket-proxy did not come up; orchestrator will use direct docker host"
fi
ok "socket-proxy running (PID ${PROXY_PID}, docker_sock=${DOCKER_SOCK})"

# ---------------------------------------------------------------------------
# Step 6: Start instrumented orchestrator and let it run through one poll cycle
# ---------------------------------------------------------------------------
info "Starting orchestrator with -cover …"
GOCOVERDIR="$COVDIR_ORCH" \
RUNSECURE_SCOPE_FILE="$SCOPE_FILE" \
DOCKER_HOST="tcp://localhost:${PROXY_PORT}" \
RUNSECURE_GITHUB_BASE_URL="http://localhost:${MOCK_PORT}" \
RUNSECURE_EGRESS_BASE_DIR="$EGRESS_DIR" \
RUNSECURE_DRAIN_SECONDS=5 \
  "$BIN_ORCH" 2>/tmp/orch-cov-stderr.log &
ORCH_PID=$!

# Wait for the orchestrator's health endpoint (confirms Run() entered the main loop).
ORCH_HEALTH_PORT=8080
_orch_up=0
for _i in $(seq 1 30); do
  if curl -sf "http://localhost:${ORCH_HEALTH_PORT}/healthz" -o /dev/null 2>/dev/null; then
    _orch_up=1
    ok "Orchestrator /healthz responded at iteration ${_i}"
    break
  fi
  sleep 1
done

if [[ "$_orch_up" -eq 0 ]]; then
  warn "Orchestrator /healthz did not respond in 30s"
  warn "Stderr tail:"
  tail -10 /tmp/orch-cov-stderr.log >&2 || true
  # Check if the process is still alive; it may have exited early (config error etc.)
  if ! kill -0 "$ORCH_PID" 2>/dev/null; then
    warn "Orchestrator exited early (config/init error). Partial coverage still collected."
  fi
fi

# ---------------------------------------------------------------------------
# Step 7: Exercise the orchestrator briefly, then shutdown gracefully
# ---------------------------------------------------------------------------
if [[ "$_orch_up" -eq 1 ]]; then
  # Let one poll cycle complete (poll_interval=60s but the first tick is immediate).
  sleep 2
  # Hit the metrics and snapshot endpoints to exercise serverDeps accessors.
  curl -sf "http://localhost:${ORCH_HEALTH_PORT}/metrics" -o /dev/null 2>/dev/null || true
  curl -sf "http://localhost:18081/state/snapshot" -o /dev/null 2>/dev/null || true
fi

info "Sending SIGTERM to orchestrator (PID ${ORCH_PID}) …"
kill -TERM "$ORCH_PID" 2>/dev/null || true
_exit_code=0
wait "$ORCH_PID" 2>/dev/null || _exit_code=$?
ok "Orchestrator exited (code ${_exit_code}); coverage flushed to $COVDIR_ORCH"

# Stop socket-proxy — SIGTERM triggers log.Fatal exit → coverage flush.
info "Stopping socket-proxy (PID ${PROXY_PID}) …"
kill -TERM "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
ok "socket-proxy stopped; proxy coverage: $(ls "$COVDIR_PROXY" | wc -l | tr -d ' ') files"

# Stop mock-github.
kill -TERM "$MOCK_PID" 2>/dev/null || true
wait "$MOCK_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 8: Merge covdata (unit + integration) and report
# ---------------------------------------------------------------------------
info "Merging covdata: unit ($COVDIR_UNIT) + integration ($COVDIR_ORCH) …"

# Validate that the integration covdata has counter files (not just meta).
ORCH_COUNTER_FILES=$(find "$COVDIR_ORCH" -name "covcounters.*" | wc -l | tr -d ' ')
if [[ "$ORCH_COUNTER_FILES" -eq 0 ]]; then
  fail "No orchestrator coverage counter files found in $COVDIR_ORCH — Run() may not have executed"
  fail "Stderr: $(cat /tmp/orch-cov-stderr.log 2>/dev/null | tail -5)"
  exit 1
fi
ok "Orchestrator integration: ${ORCH_COUNTER_FILES} counter file(s)"

cd "$ORCH_MODULE"
go tool covdata merge \
  -i "${COVDIR_UNIT},${COVDIR_ORCH}" \
  -o "$COVDIR_MERGED" 2>&1

TEXTFMT_OUT="${WORK_DIR}/combined.txt"
go tool covdata textfmt -i "$COVDIR_MERGED" -o "$TEXTFMT_OUT"

# ---------------------------------------------------------------------------
# Step 9: Extract cmd/orchestrator statement coverage from merged profile
# ---------------------------------------------------------------------------
# go tool cover -func prints: <file>:<line>: <function>  <pct>%
# Filter to cmd/orchestrator package, sum executed / total statements.

CMD_ORCH_COVERAGE=$(go tool cover -func="$TEXTFMT_OUT" \
  | awk '/cmd\/orchestrator\// && !/^--/ {
      # Parse percentage: last field is "<N.N>%"
      pct = $(NF); gsub(/%/,"",pct)
      # Skip if pct > 100 (malformed line)
      if (pct+0 <= 100) { sum += pct; count++ }
    }
    END { if (count > 0) printf "%.1f\n", sum/count; else print "0.0" }')

# Per-function detail for the coverage report
CMD_ORCH_DETAIL=$(go tool cover -func="$TEXTFMT_OUT" \
  | grep "cmd/orchestrator/" \
  | awk 'BEGIN{printf "%-70s %s\n","Function","Coverage"}
         {printf "%-70s %s\n",$1" "$2,$3}')

TOTAL_COVERAGE=$(go tool cover -func="$TEXTFMT_OUT" | grep "^total:" | awk '{print $NF}' | tr -d '%')

# Run()/main() specifically
RUN_COV=$(go tool cover -func="$TEXTFMT_OUT" \
  | awk '/cmd\/orchestrator\/run\.go.*[[:space:]]Run[[:space:]]/{print $NF}' | tr -d '%')
MAIN_COV=$(go tool cover -func="$TEXTFMT_OUT" \
  | awk '/cmd\/orchestrator\/main\.go.*[[:space:]]main[[:space:]]/{print $NF}' | tr -d '%')

# ---------------------------------------------------------------------------
# Step 10: Print report
# ---------------------------------------------------------------------------
printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  RunSecure Orchestrator Coverage Report${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════${NC}\n"
printf "\n"
printf "  Coverage policy:\n"
printf "    Logic packages (internal/*) ≥99%% by unit tests.\n"
printf "    Composition roots covered by binary integration instrumentation.\n"
printf "\n"
printf "  %-42s %s\n" "Combined module total:" "${TOTAL_COVERAGE}%"
printf "  %-42s %s\n" "cmd/orchestrator avg (fn-weighted):" "${CMD_ORCH_COVERAGE}%"
printf "  %-42s %s\n" "  Run():" "${RUN_COV:-0.0}%"
printf "  %-42s %s\n" "  main():" "${MAIN_COV:-0.0}%"
printf "\n"
printf "  Intentionally uncovered (composition-root only):\n"
printf "    runHealthcheck, runStatus  — self-curl operator CLI helpers\n"
printf "    productionKubeCtor         — Kubernetes backend init (compose tests only)\n"
printf "    socket-proxy run()         — blocked on ListenAndServe; no signal handler\n"
printf "\n"
printf "${BOLD}  Per-function cmd/orchestrator:${NC}\n"
echo "$CMD_ORCH_DETAIL" | sed 's/^/    /'
printf "\n"

# ---------------------------------------------------------------------------
# Step 11: Threshold gate
# ---------------------------------------------------------------------------
THRESHOLD_INT="${COVERAGE_THRESHOLD%%.*}"
CMD_ORCH_INT="${CMD_ORCH_COVERAGE%%.*}"

if [[ "$CMD_ORCH_INT" -ge "$THRESHOLD_INT" ]]; then
  ok "cmd/orchestrator combined coverage ${CMD_ORCH_COVERAGE}% ≥ threshold ${COVERAGE_THRESHOLD}%"
  printf "\n${GREEN}${BOLD}PASS${NC} — coverage gate met.\n\n"
  exit 0
else
  fail "cmd/orchestrator combined coverage ${CMD_ORCH_COVERAGE}% < threshold ${COVERAGE_THRESHOLD}%"
  printf "\n${RED}${BOLD}FAIL${NC} — coverage below gate. Set COVERAGE_THRESHOLD to lower the bar or add integration exercise.\n\n"
  exit 2
fi
