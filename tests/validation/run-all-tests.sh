#!/bin/bash
# ============================================================================
# RunSecure — Full Validation Suite
# ============================================================================
# Builds images, runs test projects inside containers, and validates both
# security hardening and CI capability.
#
# Usage:
#   ./tests/validation/run-all-tests.sh
#   ./tests/validation/run-all-tests.sh --skip-build    # reuse cached images
#   ./tests/validation/run-all-tests.sh --quick          # skip rust (slow build)
#
# Prerequisites:
#   - Docker running
#   - yq installed (brew install yq)
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TESTS_DIR="${RUNSECURE_ROOT}/tests"

SKIP_BUILD=false
QUICK=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --quick)      QUICK=true ;;
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
    local name="$1"
    local reason="$2"
    RESULTS+=("${YELLOW}○${NC} $name — $reason")
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

HARDENING_FLAGS=(
    --rm
    --user 1001:0
    --security-opt=no-new-privileges
    --cap-drop=ALL
    --tmpfs "/tmp:rw,nosuid,size=2g,uid=1001,gid=0"
    --memory=4g
    --memory-swap=4g
    --cpus=2
    --pids-limit=512
)

echo -e "${BOLD}=== RunSecure Validation Suite ===${NC}"
echo ""

# ============================================================================
# Phase 1: Build Images
# ============================================================================
if [[ "$SKIP_BUILD" == false ]]; then
    echo -e "${BOLD}--- Phase 1: Building Images ---${NC}\n"

    step "Build runner-base" \
        docker build -f "${RUNSECURE_ROOT}/images/base.Dockerfile" \
        -t runner-base:latest "${RUNSECURE_ROOT}"

    step "Build runner-node:24" \
        docker build -f "${RUNSECURE_ROOT}/images/node.Dockerfile" \
        --build-arg BASE_TAG=latest \
        --build-arg NODE_VERSION=24 \
        -t runner-node:24 "${RUNSECURE_ROOT}"

    step "Build runner-python:3.12" \
        docker build -f "${RUNSECURE_ROOT}/images/python.Dockerfile" \
        --build-arg BASE_TAG=latest \
        --build-arg PYTHON_VERSION=3.12 \
        -t runner-python:3.12 "${RUNSECURE_ROOT}"

    if [[ "$QUICK" == false ]]; then
        step "Build runner-rust:stable" \
            docker build -f "${RUNSECURE_ROOT}/images/rust.Dockerfile" \
            --build-arg BASE_TAG=latest \
            --build-arg RUST_VERSION=stable \
            -t runner-rust:stable "${RUNSECURE_ROOT}"
    else
        skip_step "Build runner-rust:stable" "--quick mode"
    fi
else
    echo -e "${YELLOW}Skipping image builds (--skip-build)${NC}\n"
fi

# ============================================================================
# Phase 2: Security Validation
# ============================================================================
echo -e "\n${BOLD}--- Phase 2: Security Validation ---${NC}\n"

step "Security: runner-base" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${SCRIPT_DIR}/validate-runner.sh:/home/runner/validate.sh:ro" \
    runner-base:latest bash /home/runner/validate.sh

step "Security: runner-node:24" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${SCRIPT_DIR}/validate-runner.sh:/home/runner/validate.sh:ro" \
    runner-node:24 bash /home/runner/validate.sh

step "Security: runner-python:3.12" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${SCRIPT_DIR}/validate-runner.sh:/home/runner/validate.sh:ro" \
    runner-python:3.12 bash /home/runner/validate.sh

if [[ "$QUICK" == false ]]; then
    step "Security: runner-rust:stable" \
        docker run "${HARDENING_FLAGS[@]}" \
        -v "${SCRIPT_DIR}/validate-runner.sh:/home/runner/validate.sh:ro" \
        runner-rust:stable bash /home/runner/validate.sh
else
    skip_step "Security: runner-rust:stable" "--quick mode"
fi

# ============================================================================
# Phase 3: Functional Tests (run real project test suites)
# ============================================================================
echo -e "\n${BOLD}--- Phase 3: Functional Tests ---${NC}\n"

# Projects are bind-mounted read-only where possible, or copied for write tests.

# Node.js: run test suite inside container
step "Node.js: npm test" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${TESTS_DIR}/node-project:/home/runner/_work/project:ro" \
    runner-node:24 bash -c "
        cd /home/runner/_work/project
        node --test src/*.test.js
    "

# Node.js: build step (needs writable dir for dist/)
step "Node.js: build" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${TESTS_DIR}/node-project:/mnt/project:ro" \
    runner-node:24 bash -c "
        cp -r /mnt/project /home/runner/_work/project
        cd /home/runner/_work/project
        node scripts/build.js
        cat dist/build-info.json
    "

# Python: run test suite inside container
step "Python: pytest" \
    docker run "${HARDENING_FLAGS[@]}" \
    -v "${TESTS_DIR}/python-project:/mnt/project:ro" \
    runner-python:3.12 bash -c "
        cp -r /mnt/project /home/runner/_work/project
        cd /home/runner/_work/project
        pip3 install --user --quiet --break-system-packages pytest
        python3 -m pytest tests/ -v
    "

# Rust: cargo test
if [[ "$QUICK" == false ]]; then
    step "Rust: cargo test" \
        docker run "${HARDENING_FLAGS[@]}" \
        -v "${TESTS_DIR}/rust-project:/mnt/project:ro" \
        runner-rust:stable bash -c "
            cp -r /mnt/project /home/runner/_work/project
            cd /home/runner/_work/project
            cargo test 2>&1
        "
else
    skip_step "Rust: cargo test" "--quick mode"
fi

# ============================================================================
# Phase 4: Unit Tests (host-side script tests — no Docker needed)
# ============================================================================
echo -e "\n${BOLD}--- Phase 4: Unit Tests (Script Validation) ---${NC}\n"

step "Unit: generate-squid-conf.sh" \
    bash "${TESTS_DIR}/unit/test-generate-squid-conf.sh"

step "Unit: compose-image.sh" \
    bash "${TESTS_DIR}/unit/test-compose-image.sh"

step "Unit: run.sh argument parsing" \
    bash "${TESTS_DIR}/unit/test-run-args.sh"

step "Unit: runner.yml schema validation" \
    bash "${TESTS_DIR}/unit/test-runner-yml-schema.sh"

# ============================================================================
# Phase 5: Tool Recipe Smoke Tests
# ============================================================================
echo -e "\n${BOLD}--- Phase 5: Tool Recipe Smoke Tests ---${NC}\n"

if [[ "$QUICK" == false ]]; then
    step "Tool recipes: cypress, playwright, semgrep" \
        bash "${TESTS_DIR}/validation/test-tool-recipes.sh"
else
    skip_step "Tool recipe smoke tests" "--quick mode"
fi

# ============================================================================
# Phase 6: Hardening Idempotency
# ============================================================================
echo -e "\n${BOLD}--- Phase 6: Hardening Idempotency ---${NC}\n"

step "Hardening: finalize-hardening.sh idempotency" \
    bash "${TESTS_DIR}/validation/test-hardening-idempotency.sh"

# ============================================================================
# Phase 7: Edge Cases
# ============================================================================
echo -e "\n${BOLD}--- Phase 7: Edge Case Validation ---${NC}\n"

# Verify container auto-destruction
step "Container cleanup (--rm)" bash -c "
    CONTAINER_ID=\$(docker run -d \
        --user 1001:0 \
        --security-opt=no-new-privileges \
        --cap-drop=ALL \
        --tmpfs /tmp:rw,noexec,nosuid \
        --rm \
        runner-base:latest sleep 1)
    sleep 3
    if docker inspect \$CONTAINER_ID &>/dev/null; then
        echo 'Container still exists after exit!'
        exit 1
    else
        echo 'Container auto-removed after exit.'
        exit 0
    fi
"

# Verify system paths are protected by Unix permissions
step "System paths protected" \
    docker run "${HARDENING_FLAGS[@]}" \
    runner-base:latest bash -c "
        if touch /usr/bin/backdoor 2>/dev/null; then
            echo 'ERROR: Runner user can write to /usr/bin'
            exit 1
        fi
        echo 'System paths properly protected by permissions.'
    "

# Verify fork bomb protection (PID limit)
# The test succeeds if fork() fails with "Resource temporarily unavailable"
step "PID limit enforcement" \
    docker run "${HARDENING_FLAGS[@]}" \
    --pids-limit=32 \
    runner-base:latest bash -c "
        # Try to spawn many processes — expect fork to fail
        FORK_FAILED=false
        for i in \$(seq 1 50); do
            if ! sleep 100 & 2>/dev/null; then
                FORK_FAILED=true
                break
            fi
        done
        wait 2>/dev/null || true
        if [[ \"\$FORK_FAILED\" == true ]]; then
            echo 'PID limit correctly prevented fork.'
            exit 0
        else
            echo 'WARNING: PID limit may not be enforced.'
            exit 1
        fi
    "

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}━━━ Results ━━━${NC}"
for r in "${RESULTS[@]}"; do
    printf "  %b\n" "$r"
done

echo ""
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}FAILED${NC} — $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL PASSED${NC} — $PASS_COUNT passed, $SKIP_COUNT skipped"
    exit 0
fi
