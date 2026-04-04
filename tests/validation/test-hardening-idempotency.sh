#!/bin/bash
# ============================================================================
# RunSecure Validation Test — Hardening Idempotency
# ============================================================================
# Verifies that finalize-hardening.sh is idempotent: running it twice
# doesn't break anything and produces the same result.
#
# This matters because tool recipes run between base hardening and
# finalization — if a tool accidentally re-adds something that
# finalize-hardening.sh removes, running it twice should still be safe.
#
# Usage:
#   ./tests/validation/test-hardening-idempotency.sh
#
# Prerequisites:
#   - Docker running
#   - runner-base:latest image built
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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

echo -e "\n${BOLD}=== Hardening Idempotency Tests ===${NC}\n"

if ! docker image inspect runner-base:latest &>/dev/null; then
    echo -e "${RED}ERROR: runner-base:latest not found. Build it first.${NC}"
    exit 1
fi

# ============================================================================
# Test 1: finalize-hardening.sh runs twice without error
# ============================================================================
echo -e "${BOLD}--- 1. Double execution ---${NC}"

OUTPUT=$(docker run --rm \
    -v "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh:/tmp/finalize.sh:ro" \
    runner-base:latest bash -c "
        # First run
        bash /tmp/finalize.sh
        FIRST_EXIT=\$?

        # Second run
        bash /tmp/finalize.sh
        SECOND_EXIT=\$?

        echo \"FIRST_EXIT=\$FIRST_EXIT\"
        echo \"SECOND_EXIT=\$SECOND_EXIT\"
    " 2>&1)

FIRST_EXIT=$(echo "$OUTPUT" | grep "FIRST_EXIT=" | cut -d= -f2)
SECOND_EXIT=$(echo "$OUTPUT" | grep "SECOND_EXIT=" | cut -d= -f2)

if [[ "$FIRST_EXIT" == "0" ]]; then
    pass "First run exits 0"
else
    fail "First run exits $FIRST_EXIT"
fi

if [[ "$SECOND_EXIT" == "0" ]]; then
    pass "Second run exits 0 (idempotent)"
else
    fail "Second run exits $SECOND_EXIT (NOT idempotent)"
fi

# ============================================================================
# Test 2: No setuid bits after double run
# ============================================================================
echo -e "\n${BOLD}--- 2. Setuid bits after double run ---${NC}"

SETUID_COUNT=$(docker run --rm \
    -v "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh:/tmp/finalize.sh:ro" \
    runner-base:latest bash -c "
        bash /tmp/finalize.sh &>/dev/null
        bash /tmp/finalize.sh &>/dev/null
        find / -perm /6000 -type f 2>/dev/null | wc -l
    " 2>&1 | tail -1)

if [[ "$SETUID_COUNT" == "0" ]]; then
    pass "No setuid/setgid binaries after double run"
else
    fail "Found $SETUID_COUNT setuid/setgid binaries after double run"
fi

# ============================================================================
# Test 3: /etc permissions after double run
# ============================================================================
echo -e "\n${BOLD}--- 3. /etc permissions after double run ---${NC}"

ETC_PERMS=$(docker run --rm \
    -v "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh:/tmp/finalize.sh:ro" \
    runner-base:latest bash -c "
        bash /tmp/finalize.sh &>/dev/null
        bash /tmp/finalize.sh &>/dev/null
        stat -c '%a' /etc
    " 2>&1 | tail -1)

if [[ "$ETC_PERMS" == "555" ]]; then
    pass "/etc is 555 after double run"
else
    fail "/etc is $ETC_PERMS after double run (expected 555)"
fi

# ============================================================================
# Test 4: /etc/passwd and /etc/group permissions
# ============================================================================
echo -e "\n${BOLD}--- 4. /etc/passwd and /etc/group permissions ---${NC}"

PERMS=$(docker run --rm \
    -v "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh:/tmp/finalize.sh:ro" \
    runner-base:latest bash -c "
        bash /tmp/finalize.sh &>/dev/null
        bash /tmp/finalize.sh &>/dev/null
        echo \"passwd=\$(stat -c '%a' /etc/passwd)\"
        echo \"group=\$(stat -c '%a' /etc/group)\"
    " 2>&1)

PASSWD_PERM=$(echo "$PERMS" | grep "passwd=" | cut -d= -f2)
GROUP_PERM=$(echo "$PERMS" | grep "group=" | cut -d= -f2)

if [[ "$PASSWD_PERM" == "444" ]]; then
    pass "/etc/passwd is 444"
else
    fail "/etc/passwd is $PASSWD_PERM (expected 444)"
fi

if [[ "$GROUP_PERM" == "444" ]]; then
    pass "/etc/group is 444"
else
    fail "/etc/group is $GROUP_PERM (expected 444)"
fi

# ============================================================================
# Test 5: apt is still removed after double run
# ============================================================================
echo -e "\n${BOLD}--- 5. apt removal persists ---${NC}"

APT_EXISTS=$(docker run --rm \
    -v "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh:/tmp/finalize.sh:ro" \
    runner-base:latest bash -c "
        bash /tmp/finalize.sh &>/dev/null
        bash /tmp/finalize.sh &>/dev/null
        if command -v apt-get &>/dev/null; then echo EXISTS; else echo REMOVED; fi
    " 2>&1 | tail -1)

if [[ "$APT_EXISTS" == "REMOVED" ]]; then
    pass "apt-get still removed after double run"
else
    fail "apt-get exists after double run"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Hardening Idempotency Results ===${NC}"
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
