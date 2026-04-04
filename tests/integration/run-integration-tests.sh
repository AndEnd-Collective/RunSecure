#!/bin/bash
# ============================================================================
# RunSecure — Integration Test Orchestrator
# ============================================================================
# Runs the full integration test suite:
#   1. Builds runner images (if needed)
#   2. Builds Squid proxy image
#   3. Runs egress proxy tests (allowed/blocked domains, URL filtering, proxy verification)
#   4. Runs Node.js CI workflow simulation
#   5. Runs Python CI workflow simulation
#   6. Runs Rust CI workflow simulation
#   7. Runs attack simulation tests
#   8. Runs entrypoint tests
#   9. Tears down everything, reports results
#
# Usage:
#   ./tests/integration/run-integration-tests.sh
#   ./tests/integration/run-integration-tests.sh --skip-build
#   ./tests/integration/run-integration-tests.sh --test egress    # single suite
#   ./tests/integration/run-integration-tests.sh --test node
#   ./tests/integration/run-integration-tests.sh --test python
#   ./tests/integration/run-integration-tests.sh --test rust
#   ./tests/integration/run-integration-tests.sh --test attack
#   ./tests/integration/run-integration-tests.sh --test entrypoint
#
# Prerequisites:
#   - Docker running
#   - runner-base, runner-node:24, runner-python:3.12, runner-rust:stable images built
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.test.yml"

# Auto-detect docker compose command (v2 plugin vs standalone)
if docker compose version &>/dev/null; then
    DC="docker compose"
elif docker-compose version &>/dev/null; then
    DC="docker-compose"
else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' found."
    exit 1
fi

SKIP_BUILD=false
SINGLE_TEST=""

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --test)       ;; # handled below
        egress|node|python|rust|attack|entrypoint) SINGLE_TEST="$arg" ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=()

step() {
    local name="$1"
    shift
    printf "\n${BOLD}━━━ %s ━━━${NC}\n" "$name"
    local start_time
    start_time=$(date +%s)
    if "$@"; then
        local elapsed=$(( $(date +%s) - start_time ))
        RESULTS+=("${GREEN}✓${NC} $name ${BOLD}(${elapsed}s)${NC}")
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        local elapsed=$(( $(date +%s) - start_time ))
        RESULTS+=("${RED}✗${NC} $name ${BOLD}(${elapsed}s)${NC}")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

skip_step() {
    RESULTS+=("${YELLOW}○${NC} $1 — $2")
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# Clean up on exit
cleanup() {
    echo -e "\n${BOLD}--- Cleanup ---${NC}"
    $DC -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${BOLD}=== RunSecure Integration Tests ===${NC}\n"

# ============================================================================
# Phase 0: Build Images
# ============================================================================
if [[ "$SKIP_BUILD" == false ]]; then
    echo -e "${BOLD}--- Phase 0: Building Images ---${NC}"

    # Build base if not cached
    if ! docker image inspect runner-base:latest &>/dev/null; then
        step "Build runner-base" \
            docker build -f "${RUNSECURE_ROOT}/images/base.Dockerfile" \
            -t runner-base:latest "${RUNSECURE_ROOT}"
    else
        skip_step "Build runner-base" "cached"
    fi

    # Build node
    if ! docker image inspect runner-node:24 &>/dev/null; then
        step "Build runner-node:24" \
            docker build -f "${RUNSECURE_ROOT}/images/node.Dockerfile" \
            --build-arg BASE_TAG=latest --build-arg NODE_VERSION=24 \
            -t runner-node:24 "${RUNSECURE_ROOT}"
    else
        skip_step "Build runner-node:24" "cached"
    fi

    # Build python
    if ! docker image inspect runner-python:3.12 &>/dev/null; then
        step "Build runner-python:3.12" \
            docker build -f "${RUNSECURE_ROOT}/images/python.Dockerfile" \
            --build-arg BASE_TAG=latest --build-arg PYTHON_VERSION=3.12 \
            -t runner-python:3.12 "${RUNSECURE_ROOT}"
    else
        skip_step "Build runner-python:3.12" "cached"
    fi

    # Build rust
    if ! docker image inspect runner-rust:stable &>/dev/null; then
        step "Build runner-rust:stable" \
            docker build -f "${RUNSECURE_ROOT}/images/rust.Dockerfile" \
            --build-arg BASE_TAG=latest --build-arg RUST_VERSION=stable \
            -t runner-rust:stable "${RUNSECURE_ROOT}"
    else
        skip_step "Build runner-rust:stable" "cached"
    fi

    # Build squid proxy
    step "Build squid proxy" \
        docker build -f "${RUNSECURE_ROOT}/infra/squid/Dockerfile" \
        -t runsecure-proxy:latest "${RUNSECURE_ROOT}/infra/squid"
fi

# Helper: run a test script via docker-compose
run_compose_test() {
    local test_script="$1"
    local runner_image="$2"
    local test_name="$3"

    # Tear down any previous run
    $DC -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

    TEST_SCRIPT="$test_script" \
    RUNNER_IMAGE="$runner_image" \
    $DC -f "$COMPOSE_FILE" up \
        --build \
        --abort-on-container-exit \
        --exit-code-from runner 2>&1

    local exit_code=$?

    # Always tear down
    $DC -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

    return $exit_code
}

# ============================================================================
# Phase 1: Egress Proxy Tests
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "egress" ]]; then
    echo -e "\n${BOLD}--- Phase 1: Egress Proxy Tests ---${NC}"
    step "Egress: allowed & blocked domains" \
        run_compose_test "test-egress-proxy.sh" "runner-node:24" "egress"
else
    skip_step "Egress proxy tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 2: Node.js CI Workflow
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "node" ]]; then
    echo -e "\n${BOLD}--- Phase 2: Node.js CI Workflow ---${NC}"
    step "Node CI: clone → install → test → build" \
        run_compose_test "test-ci-workflow-node.sh" "runner-node:24" "node"
else
    skip_step "Node.js CI workflow" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 3: Python CI Workflow
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "python" ]]; then
    echo -e "\n${BOLD}--- Phase 3: Python CI Workflow ---${NC}"
    step "Python CI: pip install → pytest" \
        run_compose_test "test-ci-workflow-python.sh" "runner-python:3.12" "python"
else
    skip_step "Python CI workflow" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 4: Rust CI Workflow
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "rust" ]]; then
    echo -e "\n${BOLD}--- Phase 4: Rust CI Workflow ---${NC}"
    step "Rust CI: cargo build → cargo test → crate fetch" \
        run_compose_test "test-ci-workflow-rust.sh" "runner-rust:stable" "rust"
else
    skip_step "Rust CI workflow" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 5: Attack Simulation
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "attack" ]]; then
    echo -e "\n${BOLD}--- Phase 5: Attack Simulation ---${NC}"
    step "Attack sim: escape, escalation, exfil, persistence" \
        run_compose_test "test-attack-simulation.sh" "runner-node:24" "attack"
else
    skip_step "Attack simulation" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 6: Entrypoint Tests
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "entrypoint" ]]; then
    echo -e "\n${BOLD}--- Phase 6: Entrypoint Tests ---${NC}"
    step "Entrypoint: JIT validation, proxy env, credential sanitization" \
        run_compose_test "test-entrypoint.sh" "runner-node:24" "entrypoint"
else
    skip_step "Entrypoint tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}━━━ Integration Test Results ━━━${NC}"
for r in "${RESULTS[@]}"; do
    printf "  %b\n" "$r"
done

echo ""
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}INTEGRATION TESTS FAILED${NC} — $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL INTEGRATION TESTS PASSED${NC} — $PASS_COUNT passed, $SKIP_COUNT skipped"
    exit 0
fi
