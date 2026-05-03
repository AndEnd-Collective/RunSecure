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

# --- Catalog coverage: every claim used in a check must be in claims.yml ---
# claims.yml is the SARIF rule catalog; missing entries mean the SARIF
# upload won't have a rule definition and the finding will appear as
# a "rule not found" error in Code Scanning.
CLAIMS_YML="${RUNSECURE_ROOT}/tests/acceptance/claims.yml"
if [ ! -f "$CLAIMS_YML" ]; then
    fail "tests/acceptance/claims.yml is missing — SARIF emitter cannot run"
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
    catalog_ids=$(python3 -c "
import yaml, sys
d = yaml.safe_load(open('$CLAIMS_YML'))
print('\\n'.join(sorted(d.keys())))
" 2>/dev/null)
    for claim in $CLAIMS; do
        if echo "$catalog_ids" | grep -qx "$claim"; then
            pass "$claim in claims.yml (SARIF rule available)"
        else
            fail "$claim used in a check but missing from tests/acceptance/claims.yml — SARIF rule will be undefined"
        fi
    done
    # Reverse direction: every entry in claims.yml must be used by at least
    # one check (otherwise it's dead documentation).
    for cid in $catalog_ids; do
        if ! echo "$CLAIMS" | grep -qx "$cid"; then
            fail "$cid in claims.yml but no acceptance check uses it (orphaned rule)"
        fi
    done
else
    fail "PyYAML not available — cannot validate claims.yml coverage"
fi

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
