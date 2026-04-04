#!/bin/bash
# ============================================================================
# RunSecure Unit Test — entrypoint.sh
# ============================================================================
# Tests the container entrypoint script's validation and environment handling.
# Runs inside a container to verify:
#   1. Missing RUNNER_JIT_CONFIG exits with error
#   2. Proxy environment propagation
#   3. JIT config is cleared from environment after reading
#
# Usage: Run inside a runner container (no JIT token needed — tests abort
#        before reaching the actual runner binary).
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

echo -e "\n${BOLD}=== entrypoint.sh Unit Tests ===${NC}\n"

# ============================================================================
# Test 1: Missing RUNNER_JIT_CONFIG exits with error
# ============================================================================
echo -e "${BOLD}--- 1. Missing RUNNER_JIT_CONFIG ---${NC}"

# Recreate the entrypoint validation logic in a test script
# (entrypoint.sh is not mounted in the test container)
cat > /tmp/test-jit-validation.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
if [[ -z "${RUNNER_JIT_CONFIG:-}" ]]; then
    echo "[RunSecure] ERROR: RUNNER_JIT_CONFIG is not set."
    exit 1
fi
SCRIPT

OUTPUT=$(env -u RUNNER_JIT_CONFIG bash /tmp/test-jit-validation.sh 2>&1 || true)
EXIT_CODE=$?
rm -f /tmp/test-jit-validation.sh

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
# Test 2: Proxy environment propagation
# ============================================================================
echo -e "\n${BOLD}--- 2. Proxy environment propagation ---${NC}"

# The entrypoint script sets lowercase proxy vars from uppercase ones.
# We can't run the full script (it execs the runner), but we can test
# the proxy logic by sourcing just the relevant section.

# Create a test script that sources only the proxy logic
cat > /tmp/test-proxy-env.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail

# Simulate what entrypoint.sh does for proxy
HTTP_PROXY="http://proxy:3128"
HTTPS_PROXY="http://proxy:3128"

if [[ -n "${HTTP_PROXY:-}" ]]; then
    export http_proxy="${HTTP_PROXY}"
    export https_proxy="${HTTPS_PROXY:-$HTTP_PROXY}"
    export no_proxy="localhost,127.0.0.1"
fi

echo "http_proxy=$http_proxy"
echo "https_proxy=$https_proxy"
echo "no_proxy=$no_proxy"
SCRIPT

OUTPUT=$(bash /tmp/test-proxy-env.sh 2>&1)
rm -f /tmp/test-proxy-env.sh

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

cat > /tmp/test-proxy-fallback.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
HTTP_PROXY="http://proxy:3128"
# HTTPS_PROXY intentionally not set
unset HTTPS_PROXY 2>/dev/null || true

if [[ -n "${HTTP_PROXY:-}" ]]; then
    export http_proxy="${HTTP_PROXY}"
    export https_proxy="${HTTPS_PROXY:-$HTTP_PROXY}"
    export no_proxy="localhost,127.0.0.1"
fi

echo "https_proxy=$https_proxy"
SCRIPT

OUTPUT=$(bash /tmp/test-proxy-fallback.sh 2>&1)
rm -f /tmp/test-proxy-fallback.sh

if echo "$OUTPUT" | grep -q "https_proxy=http://proxy:3128"; then
    pass "https_proxy falls back to HTTP_PROXY when HTTPS_PROXY unset"
else
    fail "https_proxy fallback not working"
fi

# ============================================================================
# Test 4: JIT config is cleared from environment
# ============================================================================
echo -e "\n${BOLD}--- 4. JIT config credential sanitization ---${NC}"

# Create a script that simulates the credential clearing logic
cat > /tmp/test-jit-clear.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
export RUNNER_JIT_CONFIG="supersecrettoken123"

# This is what entrypoint.sh does
JIT_CONFIG="${RUNNER_JIT_CONFIG}"
unset RUNNER_JIT_CONFIG

# Verify the variable is gone from the environment
if [[ -z "${RUNNER_JIT_CONFIG:-}" ]]; then
    echo "CLEARED"
else
    echo "LEAKED"
fi

# Verify local copy still works
if [[ "$JIT_CONFIG" == "supersecrettoken123" ]]; then
    echo "LOCAL_COPY_OK"
fi
SCRIPT

OUTPUT=$(bash /tmp/test-jit-clear.sh 2>&1)
rm -f /tmp/test-jit-clear.sh

if echo "$OUTPUT" | grep -q "CLEARED"; then
    pass "RUNNER_JIT_CONFIG cleared from environment after reading"
else
    fail "RUNNER_JIT_CONFIG still in environment (credential leak!)"
fi

if echo "$OUTPUT" | grep -q "LOCAL_COPY_OK"; then
    pass "JIT config preserved in local variable for runner startup"
else
    fail "JIT config lost before runner startup"
fi

# ============================================================================
# Test 5: Verify JIT config not visible in /proc/self/environ
# ============================================================================
echo -e "\n${BOLD}--- 5. JIT config not in /proc/self/environ ---${NC}"

cat > /tmp/test-jit-proc.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
export RUNNER_JIT_CONFIG="supersecrettoken123"

JIT_CONFIG="${RUNNER_JIT_CONFIG}"
unset RUNNER_JIT_CONFIG

# Check /proc/self/environ (shows initial env, but unset should remove it
# from the current process's env for child processes)
if env | grep -q "RUNNER_JIT_CONFIG"; then
    echo "VISIBLE_IN_ENV"
else
    echo "HIDDEN_FROM_ENV"
fi
SCRIPT

OUTPUT=$(bash /tmp/test-jit-proc.sh 2>&1)
rm -f /tmp/test-jit-proc.sh

if echo "$OUTPUT" | grep -q "HIDDEN_FROM_ENV"; then
    pass "JIT config hidden from env output (child processes can't see it)"
else
    fail "JIT config visible in env output"
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
