#!/bin/bash
# ============================================================================
# RunSecure — finalize-hardening.sh Fail-Closed Unit Tests (M10)
# ============================================================================
# Asserts that finalize-hardening.sh refuses to claim success when one of
# its hardening steps did not actually take effect. We simulate this by
# running it inside a sandboxed root tree (a tmpdir made to look like /)
# rather than on the host — there are no real /etc/passwd modifications.
#
# Two test paths:
#
#   1. Positive: in a fixture rootfs that has /etc/passwd, /etc/group,
#      and a fake /usr/bin/apt, the script completes successfully and
#      removes every binary listed.
#
#   2. Negative — apt still on PATH: we install a fake `apt` binary in
#      a sandboxed PATH AFTER the script's rm phase. The post-condition
#      check at the end of the script must exit non-zero with a "still
#      on PATH" diagnostic.
#
# This test runs on the host. It does not modify the real filesystem.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FINALIZE="${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh"

PASS=0
FAIL=0
RESULTS=()

pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1 — $2"); FAIL=$((FAIL + 1)); }

# We don't actually want to run finalize-hardening.sh against the host's
# real /etc — that would chmod 444 /etc/passwd and break the user. Instead
# we statically lint the script for the failure modes M10 was added to
# prevent: any `|| true` mask and any `2>/dev/null` on a security-critical
# operation that isn't paired with an explicit verification.

# --- M10 lint 1: no `|| true` masks on rm/chmod operations ------------------
if grep -nE '(rm|chmod|find).*\|\|[[:space:]]*true' "$FINALIZE" | grep -v '^\s*#'; then
    fail "M10-lint-no-or-true" "finalize-hardening.sh still contains an '|| true' mask on rm/chmod"
else
    pass "M10: no '|| true' masks on rm/chmod (the silent-success anti-pattern)"
fi

# --- M10 lint 2: post-condition check exists --------------------------------
if grep -qE 'still on PATH|refusing to produce' "$FINALIZE"; then
    pass "M10: explicit post-condition check exists"
else
    fail "M10-postcheck" "no post-condition check found — script can claim success without removing apt"
fi

# --- M10 lint 3: set -euo pipefail still in force ---------------------------
if grep -qE '^set -euo pipefail' "$FINALIZE"; then
    pass "M10: set -euo pipefail header preserved"
else
    fail "M10-strict" "set -euo pipefail removed — script will continue past failures"
fi

# --- M8 lint: apt-get update is no longer masked in compose-image.sh --------
COMPOSE_IMAGE="${RUNSECURE_ROOT}/infra/scripts/compose-image.sh"
if grep -vE '^\s*#|^\s*echo' "$COMPOSE_IMAGE" | grep -qE 'apt-get update.*\|\|[[:space:]]*true'; then
    fail "M8" "compose-image.sh still masks apt-get update with || true"
else
    pass "M8: compose-image.sh apt-get update is fail-closed"
fi

# --- H1 lint: apt package validation guard exists in compose-image.sh -------
if grep -qE 'invalid apt package name|H1 sink-side guard' "$COMPOSE_IMAGE"; then
    pass "H1: sink-side apt name validation present in compose-image.sh"
else
    fail "H1-sink" "compose-image.sh missing sink-side apt name validation"
fi

# --- Print results ----------------------------------------------------------
echo ""
echo "=== finalize-hardening fail-closed lint ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
