#!/bin/bash
# Integration test: RUNSECURE_DIAG_RETENTION=0 kill switch.
# Prerequisite: run.sh was invoked with RUNSECURE_DIAG_RETENTION=0.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIAG_HOST_DIR="$REPO_ROOT/_diag"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

# 1. Host _diag/ should not contain Worker logs (no bind mount)
if [[ -d "$DIAG_HOST_DIR" ]]; then
    if compgen -G "$DIAG_HOST_DIR/Worker_*.log" >/dev/null 2>&1; then
        fail "host _diag/Worker_*.log exists despite RUNSECURE_DIAG_RETENTION=0"
    else
        pass "host _diag/ has no Worker_*.log (kill switch worked)"
    fi
else
    pass "host _diag/ does not exist (kill switch worked)"
fi

# 2. gh api still returns 200 (sync wait works without bind mount)
if [[ -n "${RUNSECURE_DISCOVERY_REPO:-}" && -n "${RUNSECURE_LAST_JOB_ID:-}" ]]; then
    HTTP_CODE=$(gh api "repos/$RUNSECURE_DISCOVERY_REPO/actions/jobs/$RUNSECURE_LAST_JOB_ID/logs" --include 2>&1 | head -1 | awk '{print $2}')
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "gh api returned 200 even with retention disabled"
    else
        fail "gh api returned $HTTP_CODE (expected 200)"
    fi
else
    echo "[SKIP] gh api check — RUNSECURE_DISCOVERY_REPO/RUNSECURE_LAST_JOB_ID not set"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
exit $((FAIL > 0))
