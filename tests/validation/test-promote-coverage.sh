#!/bin/bash
# ============================================================================
# RunSecure — Promote-to-Stable Coverage Lint
# ============================================================================
# Asserts every published image kind has a promote-to-stable matrix entry, so
# an image can't be built + Grype-scanned + pushed as `<ver>-canary` yet never
# promoted to the stable `<ver>` / `latest` tags.
#
# This guards the exact regression where the orchestrator + socket-proxy
# control-plane images were omitted from promote-to-stable's matrix (they were
# added to publish-images for the Compose-backed orchestrator, but the promote
# matrix was never updated), leaving operators with only `-canary` tags.
#
# Pure file-content check — no Docker required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOWS_DIR="${RUNSECURE_ROOT}/.github/workflows"
PROMOTE_WF="${WORKFLOWS_DIR}/promote-to-stable.yml"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

if [[ ! -f "$PROMOTE_WF" ]]; then
    echo "FAILED: promote-to-stable.yml not found at $PROMOTE_WF"
    exit 1
fi

# Every image kind that publish-images builds + pushes must have at least one
# `kind: <name>` entry in the promote-to-stable matrix. If you add a new
# published image, add it to promote-to-stable.yml AND list it here.
for img in base proxy orchestrator socket-proxy node python rust; do
    if grep -qE "^[[:space:]]*-?[[:space:]]*kind:[[:space:]]*${img}\b" "$PROMOTE_WF"; then
        pass "promote-to-stable.yml: '${img}' image is promoted canary→stable"
    else
        fail "promote-to-stable.yml: '${img}' image is published but NOT promoted (stuck at -canary)"
    fi
done

echo ""
echo "=== Promote-to-Stable Coverage ==="
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
