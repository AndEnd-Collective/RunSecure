#!/bin/bash
# ============================================================================
# RunSecure — Tool Recipe Pinning Lint (H9)
# ============================================================================
# Asserts that every tool recipe in tools/*.sh:
#   1. Pins its primary tool to an explicit version (no floating tag).
#   2. Tags that pin with a Renovate marker so the version constant
#      is updated automatically on a tracked PR.
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

# Each recipe must contain a "# renovate:" marker AND a versioned install
# command. The version constant must be assigned literally (not derived
# at runtime).
for recipe in "${TOOLS_DIR}"/*.sh; do
    name=$(basename "$recipe" .sh)
    upper=$(echo "$name" | tr '[:lower:]-' '[:upper:]_')

    if ! grep -qE '^# renovate: datasource=' "$recipe"; then
        fail "$name: missing '# renovate: datasource=' marker"
        continue
    fi
    pass "$name: has renovate marker"

    if ! grep -qE "^${upper}_VERSION=\"[0-9]" "$recipe"; then
        fail "$name: no ${upper}_VERSION literal pin"
        continue
    fi
    pass "$name: pins ${upper}_VERSION"

    # The version constant must be referenced at install time. We accept
    # any of these threading patterns: @"${VAR}", @${VAR}, =="${VAR}", ==${VAR}.
    if ! grep -F -q "\${${upper}_VERSION}" "$recipe"; then
        fail "$name: \${${upper}_VERSION} not threaded into the install command"
        continue
    fi
    pass "$name: install command references \${${upper}_VERSION}"
done

# --- Renovate config sanity --------------------------------------------------
RENOVATE_JSON="${RUNSECURE_ROOT}/renovate.json"
if [[ -f "$RENOVATE_JSON" ]]; then
    if grep -q 'renovate: datasource=' "${TOOLS_DIR}"/*.sh && grep -q 'tools/.*\\\\.sh' "$RENOVATE_JSON"; then
        pass "renovate.json: customManager regex matches tool recipes"
    else
        fail "renovate.json: customManager regex doesn't reference tools/*.sh"
    fi
else
    fail "renovate.json: missing"
fi

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
