#!/bin/bash
# ============================================================================
# RunSecure — Tool Recipe Pinning Lint
# ============================================================================
# Asserts that every tool recipe in tools/*.sh pins its primary tool to an
# explicit version (no floating tag) and threads that pin into the install
# command. Image determinism depends on this — without pinning, every
# rebuild can pull a different upstream version.
#
# Pure file-content checks; no Docker required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLS_DIR="${RUNSECURE_ROOT}/tools"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

for recipe in "${TOOLS_DIR}"/*.sh; do
    name=$(basename "$recipe" .sh)
    upper=$(echo "$name" | tr '[:lower:]-' '[:upper:]_')

    if ! grep -qE "^${upper}_VERSION=\"[0-9]" "$recipe"; then
        fail "$name: no ${upper}_VERSION literal pin"
        continue
    fi
    pass "$name: pins ${upper}_VERSION"

    # The version constant must be referenced at install time.
    if ! grep -F -q "\${${upper}_VERSION}" "$recipe"; then
        fail "$name: \${${upper}_VERSION} not threaded into the install command"
        continue
    fi
    pass "$name: install command references \${${upper}_VERSION}"
done

# --- Print results -----------------------------------------------------------
echo ""
echo "=== Tool Pinning Lint ==="
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
