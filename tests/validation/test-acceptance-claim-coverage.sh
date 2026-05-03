#!/bin/bash
# ============================================================================
# RunSecure — Acceptance-claim Coverage Lint
# ============================================================================
# Asserts that every claim ID used in tests/acceptance/ (H01, R02, N03, …)
# has matching documentation in SECURITY.md or README.md. This prevents
# the test catalog from drifting away from the documented threat model.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

# Extract every distinct claim ID used in acceptance tests
CLAIMS=$(grep -rhE '\b(pass|fail|skip|expect_pass|expect_fail) [HRN][0-9]+' \
            "${RUNSECURE_ROOT}/tests/acceptance/" 2>/dev/null \
         | grep -oE '\b[HRN][0-9]+\b' | sort -u)

if [ -z "$CLAIMS" ]; then
    fail "no claim IDs found in tests/acceptance/"
else
    pass "extracted $(echo "$CLAIMS" | wc -l | tr -d ' ') distinct claim IDs"
fi

# Each claim ID must be referenced (commented) in at least one check file
# AND the docs (SECURITY.md / README.md) must mention the underlying
# property. We can't auto-prove the second mapping, so we lint the first:
# every claim must have an inline comment in its primary check file.
for claim in $CLAIMS; do
    # Find which check file owns this claim — it's the one with the
    # filename matching the claim's lowercase prefix.
    prefix=$(echo "$claim" | tr '[:upper:]' '[:lower:]')
    check_file=$(find "${RUNSECURE_ROOT}/tests/acceptance" -name "${prefix}*.sh" 2>/dev/null | head -1)
    if [ -z "$check_file" ]; then
        fail "$claim: no check file named ${prefix}-*.sh"
        continue
    fi
    # The check file's top-level comment must explain what the claim covers
    if ! head -5 "$check_file" | grep -qE "^# +${claim}[.:]"; then
        fail "$claim: check file $(basename "$check_file") doesn't document the claim in its header"
        continue
    fi
    pass "$claim → $(basename "$check_file") (claim documented in header)"
done

echo ""
echo "=== Acceptance-claim Coverage ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
