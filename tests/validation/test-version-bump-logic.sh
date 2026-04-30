#!/bin/bash
# ============================================================================
# RunSecure — Weekly Version Bump Logic Unit Tests
# ============================================================================
# Exercises the version-computation logic from .github/workflows/weekly-
# version-bump.yml against a fixed input matrix. Pure shell — no GitHub
# API, no docker required.
#
# We can't run the actions/checkout step, but we CAN extract the bash
# code that computes NEXT from LATEST + BUMP_TYPE and verify it produces
# the expected output for each combination.
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1 (got: $2, expected: $3)"); FAIL=$((FAIL + 1)); }

# Replicate the workflow's bump logic verbatim (kept in sync with the
# workflow file — the lint below verifies they match).
_bump() {
    local LATEST="$1"
    local BUMP_TYPE="$2"
    if [ -z "$LATEST" ]; then
        LATEST="v0.0.0"
    fi
    local MAJOR MINOR PATCH NEXT
    MAJOR=$(echo "$LATEST" | sed -E 's/^v([0-9]+)\.[0-9]+\.[0-9]+$/\1/')
    MINOR=$(echo "$LATEST" | sed -E 's/^v[0-9]+\.([0-9]+)\.[0-9]+$/\1/')
    PATCH=$(echo "$LATEST" | sed -E 's/^v[0-9]+\.[0-9]+\.([0-9]+)$/\1/')
    case "$BUMP_TYPE" in
        major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
        minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
        patch) PATCH=$((PATCH + 1)) ;;
        *) echo "INVALID:$BUMP_TYPE"; return 1 ;;
    esac
    NEXT="v${MAJOR}.${MINOR}.${PATCH}"
    echo "$NEXT"
}

# Matrix: latest | bump | expected
expect() {
    local input="$1" bump="$2" expected="$3"
    local got
    got=$(_bump "$input" "$bump")
    if [ "$got" = "$expected" ]; then
        pass "$input + $bump → $got"
    else
        fail "$input + $bump" "$got" "$expected"
    fi
}

# --- Patch bumps (the weekly default) ----------------------------------------
expect "v0.0.0"   patch "v0.0.1"
expect "v1.0.0"   patch "v1.0.1"
expect "v1.2.3"   patch "v1.2.4"
expect "v1.2.9"   patch "v1.2.10"
expect "v0.99.99" patch "v0.99.100"
expect ""         patch "v0.0.1"          # no prior tag

# --- Minor bumps -------------------------------------------------------------
expect "v0.0.0" minor "v0.1.0"
expect "v1.2.3" minor "v1.3.0"
expect "v1.2.9" minor "v1.3.0"            # patch resets
expect ""       minor "v0.1.0"

# --- Major bumps -------------------------------------------------------------
expect "v0.0.0" major "v1.0.0"
expect "v1.2.3" major "v2.0.0"
expect "v9.5.7" major "v10.0.0"           # both minor + patch reset
expect ""       major "v1.0.0"

# --- Invalid bump type -------------------------------------------------------
got=$(_bump "v1.2.3" "wibble" 2>&1)
if echo "$got" | grep -q INVALID; then
    pass "rejects invalid bump type"
else
    fail "invalid bump type" "$got" "INVALID:wibble"
fi

# --- Lint: workflow file is sync with this test ------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="$(cd "$SCRIPT_DIR/../.." && pwd)/.github/workflows/weekly-version-bump.yml"
if [ -f "$WF" ]; then
    if grep -q 'PATCH=$((PATCH + 1))' "$WF" && \
       grep -q 'MINOR=$((MINOR + 1)); PATCH=0' "$WF" && \
       grep -q 'MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0' "$WF"; then
        pass "workflow's bump arithmetic matches this test's expected behaviour"
    else
        fail "workflow drift" "see $WF" "matching arithmetic for major/minor/patch"
    fi
else
    fail "workflow missing" "$WF" "exists"
fi

# --- Print results -----------------------------------------------------------
echo ""
echo "=== Weekly Version Bump Logic ==="
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
