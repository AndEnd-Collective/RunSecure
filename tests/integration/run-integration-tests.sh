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
#   9. Runs log-loss fix tests (host _diag/ bind mount + gh api)
#  10. Runs log-loss retention kill switch tests (RUNSECURE_DIAG_RETENTION=0)
#  11. Runs schema rejection tests (host-side, no Docker)
#  12. Runs SSRF protection tests (host-side, no Docker)
#  13. Runs TCP validation tests (host-side, no Docker)
#  14. Runs DNS config validation tests (host-side, no Docker)
#  15. Runs TCP egress deprecation tests (host-side, no Docker)
#  16. Runs TCP egress tests (Docker — requires HAProxy configured)
#  17. Runs DNS validation tests (Docker — requires dnsmasq configured)
#  18. Tears down everything, reports results
#
# Usage:
#   ./tests/integration/run-integration-tests.sh
#   ./tests/integration/run-integration-tests.sh --skip-build
#   ./tests/integration/run-integration-tests.sh --test egress              # single suite
#   ./tests/integration/run-integration-tests.sh --test node
#   ./tests/integration/run-integration-tests.sh --test python
#   ./tests/integration/run-integration-tests.sh --test rust
#   ./tests/integration/run-integration-tests.sh --test attack
#   ./tests/integration/run-integration-tests.sh --test entrypoint
#   ./tests/integration/run-integration-tests.sh --test log-loss
#   ./tests/integration/run-integration-tests.sh --test log-loss-retention
#   ./tests/integration/run-integration-tests.sh --test schema
#   ./tests/integration/run-integration-tests.sh --test ssrf
#   ./tests/integration/run-integration-tests.sh --test tcp-validate
#   ./tests/integration/run-integration-tests.sh --test dns-validate
#   ./tests/integration/run-integration-tests.sh --test tcp-deprecation
#   ./tests/integration/run-integration-tests.sh --test tcp-egress
#   ./tests/integration/run-integration-tests.sh --test dns
#
# Prerequisites:
#   - Docker running
#   - runner-base, runner-node:24, runner-python:3.12, runner-rust:stable images built
# ============================================================================

# SC2329: helper functions (cleanup, run_compose_test, run_host_test, step,
# skip_step) are invoked indirectly via "$@" or trap — shellcheck cannot
# statically trace those call sites.
# shellcheck disable=SC2329
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --test)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --test requires a value (egress|node|python|rust|attack|entrypoint|log-loss|log-loss-retention|schema|ssrf|tcp-validate|dns-validate|tcp-deprecation|tcp-egress|dns)"
                exit 1
            fi
            SINGLE_TEST="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
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

# Helper: run a host-side test script directly (no docker-compose)
run_host_test() {
    local test_script="$1"
    bash "${SCRIPT_DIR}/${test_script}"
}

# Helper: run a test script via docker-compose
run_compose_test() {
    local test_script="$1"
    local runner_image="$2"
    # $3 is test_name, kept for callers but unused internally
    shift 2

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

    return "$exit_code"
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
# Phase 7: Log-Loss Fix Tests
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "log-loss" ]]; then
    echo -e "\n${BOLD}--- Phase 7: Log-Loss Fix Tests ---${NC}"
    step "Log-loss: host _diag/ populated + gh api returns 200" \
        run_host_test "test-log-loss.sh"
else
    skip_step "Log-loss fix tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 8: Log-Loss Retention Kill Switch Tests
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "log-loss-retention" ]]; then
    echo -e "\n${BOLD}--- Phase 8: Log-Loss Retention Kill Switch Tests ---${NC}"
    step "Log-loss retention: RUNSECURE_DIAG_RETENTION=0 skips bind mount" \
        run_host_test "test-log-loss-retention-disabled.sh"
else
    skip_step "Log-loss retention kill switch" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 9: Schema Rejection Tests (host-side)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "schema" ]]; then
    echo -e "\n${BOLD}--- Phase 9: Schema Rejection Tests ---${NC}"
    step "Schema: invalid runner.yml fields and values rejected" \
        run_host_test "test-strict-schema-rejection.sh"
else
    skip_step "Schema rejection tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 10: SSRF Protection Tests (host-side)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "ssrf" ]]; then
    echo -e "\n${BOLD}--- Phase 10: SSRF Protection Tests ---${NC}"
    step "SSRF: private/reserved IP ranges blocked in fetch-runtime-file" \
        run_host_test "test-ssrf-protection.sh"
else
    skip_step "SSRF protection tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 11: TCP Validation Tests (host-side)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "tcp-validate" ]]; then
    echo -e "\n${BOLD}--- Phase 11: TCP Validation Tests ---${NC}"
    step "TCP validation: host:port format + port uniqueness enforced" \
        run_host_test "test-tcp-validation.sh"
else
    skip_step "TCP validation tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 12: DNS Config Validation Tests (host-side)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "dns-validate" ]]; then
    echo -e "\n${BOLD}--- Phase 12: DNS Config Validation Tests ---${NC}"
    step "DNS validation: dns: block schema enforcement" \
        run_host_test "test-dns-config-validation.sh"
else
    skip_step "DNS config validation tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 13: TCP Egress Deprecation Tests (host-side)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "tcp-deprecation" ]]; then
    echo -e "\n${BOLD}--- Phase 13: TCP Egress Deprecation Tests ---${NC}"
    step "TCP deprecation: old 'egress:' key still accepted alongside new keys" \
        run_host_test "test-tcp-egress-deprecation.sh"
else
    skip_step "TCP egress deprecation tests" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 14: TCP Egress Tests (Docker-based)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "tcp-egress" ]]; then
    echo -e "\n${BOLD}--- Phase 14: TCP Egress Tests (Docker) ---${NC}"
    step "TCP egress: HAProxy proxies TCP connections from runner" \
        run_compose_test "test-tcp-egress.sh" "runner-node:24" "tcp-egress"
else
    skip_step "TCP egress tests (Docker)" "--test $SINGLE_TEST"
fi

# ============================================================================
# Phase 15: DNS Validation Tests (Docker-based)
# ============================================================================
if [[ -z "$SINGLE_TEST" || "$SINGLE_TEST" == "dns" ]]; then
    echo -e "\n${BOLD}--- Phase 15: DNS Validation Tests (Docker) ---${NC}"
    step "DNS: dnsmasq serves custom records and runner uses proxy DNS" \
        run_compose_test "test-dns-validation.sh" "runner-node:24" "dns"
else
    skip_step "DNS validation tests (Docker)" "--test $SINGLE_TEST"
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
