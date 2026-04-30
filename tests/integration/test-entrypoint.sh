#!/bin/bash
# ============================================================================
# RunSecure Integration Test — entrypoint.sh
# ============================================================================
# Tests the actual entrypoint.sh script's validation and environment handling.
# Runs inside a container with the real entrypoint.sh bind-mounted.
#
# Testing strategy:
#   - The real entrypoint.sh ends with `exec ./run.sh --jitconfig ...`
#   - We create a fake run.sh that captures args/env instead of running
#   - This lets us test all real entrypoint logic (validation, proxy, creds)
#
# Usage: Run inside a runner container via docker-compose.test.yml
#   The test compose file mounts tests/ at /mnt/tests and the repo at /mnt/
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    FAIL=$((FAIL + 1))
}

REAL_ENTRYPOINT="/mnt/infra/scripts/entrypoint.sh"

echo -e "\n${BOLD}=== entrypoint.sh Integration Tests ===${NC}\n"

# Verify the real entrypoint is mounted
if [[ ! -f "$REAL_ENTRYPOINT" ]]; then
    echo -e "${RED}ERROR: $REAL_ENTRYPOINT not found. Is the repo bind-mounted at /mnt/?${NC}"
    exit 1
fi

# ============================================================================
# Test 1: Missing RUNNER_JIT_CONFIG exits with error
# ============================================================================
echo -e "${BOLD}--- 1. Missing RUNNER_JIT_CONFIG ---${NC}"

# Run the real entrypoint without RUNNER_JIT_CONFIG — it should exit 1
EXIT_CODE=0
OUTPUT=$(env -u RUNNER_JIT_CONFIG bash "$REAL_ENTRYPOINT" 2>&1) || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "Exits with non-zero code when RUNNER_JIT_CONFIG missing"
else
    fail "Exits with code 0 when RUNNER_JIT_CONFIG missing"
fi

if echo "$OUTPUT" | grep -q "RUNNER_JIT_CONFIG is not set"; then
    pass "Reports that RUNNER_JIT_CONFIG is not set"
else
    fail "Does not report missing RUNNER_JIT_CONFIG"
fi

# ============================================================================
# Set up fake runner directory for remaining tests
# ============================================================================

# Create a fake runner dir with a run.sh that dumps env and exits.
# Use $HOME because /tmp is mounted noexec in the production hardened
# runner — direct execution of `./run.sh` would fail with Permission
# denied when RUNNER_DIR is under /tmp. /home/runner is writable + exec.
FAKE_RUNNER_DIR=$(mktemp -d -p "${HOME:-/home/runner}")
trap 'rm -rf "$FAKE_RUNNER_DIR"' EXIT

# Create a fake run.sh that dumps its environment and arguments
cat > "${FAKE_RUNNER_DIR}/run.sh" <<'SCRIPT'
#!/bin/bash
echo "ENTRYPOINT_ARGS=$*"
env | sort
exit 0
SCRIPT
chmod +x "${FAKE_RUNNER_DIR}/run.sh"

# Create a fake deps file so the version detection doesn't crash
mkdir -p "${FAKE_RUNNER_DIR}/bin"
echo '{}' > "${FAKE_RUNNER_DIR}/bin/Runner.Listener.deps.json"

# Create a modified copy of entrypoint.sh that uses our fake runner dir
MODIFIED_ENTRYPOINT="${FAKE_RUNNER_DIR}/entrypoint-test.sh"
sed "s|RUNNER_DIR=\"/home/runner/actions-runner\"|RUNNER_DIR=\"${FAKE_RUNNER_DIR}\"|" \
    "$REAL_ENTRYPOINT" > "$MODIFIED_ENTRYPOINT"
chmod +x "$MODIFIED_ENTRYPOINT"

# ============================================================================
# Test 2: Proxy environment propagation
# ============================================================================
echo -e "\n${BOLD}--- 2. Proxy environment propagation ---${NC}"

OUTPUT=$(RUNNER_JIT_CONFIG="FAKE_JIT_TOKEN_FOR_TESTING" \
    HTTP_PROXY="http://proxy:3128" \
    HTTPS_PROXY="http://proxy:3128" \
    bash "$MODIFIED_ENTRYPOINT" 2>&1 || true)

if echo "$OUTPUT" | grep -q "http_proxy=http://proxy:3128"; then
    pass "http_proxy set from HTTP_PROXY"
else
    fail "http_proxy not propagated"
fi

if echo "$OUTPUT" | grep -q "https_proxy=http://proxy:3128"; then
    pass "https_proxy set from HTTPS_PROXY"
else
    fail "https_proxy not propagated"
fi

if echo "$OUTPUT" | grep -q "no_proxy=localhost,127.0.0.1"; then
    pass "no_proxy set to localhost,127.0.0.1"
else
    fail "no_proxy not set correctly"
fi

# ============================================================================
# Test 3: HTTPS_PROXY falls back to HTTP_PROXY
# ============================================================================
echo -e "\n${BOLD}--- 3. HTTPS_PROXY fallback ---${NC}"

OUTPUT=$(RUNNER_JIT_CONFIG="FAKE_JIT_TOKEN_FOR_TESTING" \
    HTTP_PROXY="http://proxy:3128" \
    bash "$MODIFIED_ENTRYPOINT" 2>&1 || true)

if echo "$OUTPUT" | grep -q "https_proxy=http://proxy:3128"; then
    pass "https_proxy falls back to HTTP_PROXY when HTTPS_PROXY unset"
else
    fail "https_proxy fallback not working"
fi

# ============================================================================
# Test 4: JIT config is cleared from environment
# ============================================================================
echo -e "\n${BOLD}--- 4. JIT config credential sanitization ---${NC}"

OUTPUT=$(RUNNER_JIT_CONFIG="FAKE_JIT_TOKEN_FOR_TESTING" \
    HTTP_PROXY="http://proxy:3128" \
    bash "$MODIFIED_ENTRYPOINT" 2>&1 || true)

# The fake run.sh dumps env — RUNNER_JIT_CONFIG should NOT appear
if echo "$OUTPUT" | grep -q "^RUNNER_JIT_CONFIG="; then
    fail "RUNNER_JIT_CONFIG still visible in child process environment (credential leak!)"
else
    pass "RUNNER_JIT_CONFIG cleared from environment before runner exec"
fi

# ============================================================================
# Test 5: JIT config is passed to the runner via --jitconfig flag
# ============================================================================
echo -e "\n${BOLD}--- 5. JIT config passed via --jitconfig ---${NC}"

OUTPUT=$(RUNNER_JIT_CONFIG="FAKE_JIT_TOKEN_FOR_TESTING" \
    HTTP_PROXY="http://proxy:3128" \
    bash "$MODIFIED_ENTRYPOINT" 2>&1 || true)

if echo "$OUTPUT" | grep -q -- "ENTRYPOINT_ARGS=--jitconfig FAKE_JIT_TOKEN_FOR_TESTING"; then
    pass "JIT config passed to runner via --jitconfig flag"
else
    fail "JIT config not passed to runner correctly"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== entrypoint.sh Test Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
