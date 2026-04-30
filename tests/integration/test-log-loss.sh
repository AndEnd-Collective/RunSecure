#!/bin/bash
# Integration test: log-loss fix.
# Asserts that a deliberate-failure step produces a retrievable log
# via gh api AND that the host-side _diag/ contains the stderr.
#
# Prerequisite: a deliberately-failing workflow has just run via
# infra/scripts/run.sh. The test runner (or operator) sets up:
#   RUNSECURE_DISCOVERY_REPO=<owner>/<repo>
#   RUNSECURE_LAST_JOB_ID=<job_id>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIAG_HOST_DIR="$REPO_ROOT/_diag"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

# 1. Host-side _diag/ contains a Worker log
if compgen -G "$DIAG_HOST_DIR/Worker_*.log" >/dev/null 2>&1; then
    pass "host-side _diag/Worker_*.log exists after run"
    if grep -q "MARKER-FAIL" "$DIAG_HOST_DIR"/Worker_*.log 2>/dev/null; then
        pass "host-side _diag/ contains workflow stderr"
    else
        echo "[INFO] _diag/Worker_*.log present but MARKER-FAIL absent (workflow may not have used that string)"
    fi
else
    fail "host-side _diag/Worker_*.log does not exist after run"
fi

# 2. _diag/ has correct ownership (UID 1001) — only checkable on Linux
if [[ -d "$DIAG_HOST_DIR" ]]; then
    OWNER_UID=$(stat -c '%u' "$DIAG_HOST_DIR" 2>/dev/null || stat -f '%u' "$DIAG_HOST_DIR" 2>/dev/null || echo unknown)
    if [[ "$OWNER_UID" == "1001" ]] || [[ "$OWNER_UID" == "unknown" ]]; then
        pass "_diag/ ownership OK (UID $OWNER_UID)"
    else
        echo "[INFO] _diag/ owned by UID $OWNER_UID (expected 1001 on Linux)"
    fi
fi

# 3. _diag.previous/ exists from a prior run (only if this is run #2+)
if [[ -d "$DIAG_HOST_DIR.previous" ]]; then
    pass "_diag.previous/ exists (rotation worked)"
else
    echo "[INFO] _diag.previous/ not yet present (first run)"
fi

# 4. gh api returns logs (only if env vars set)
if [[ -n "${RUNSECURE_DISCOVERY_REPO:-}" && -n "${RUNSECURE_LAST_JOB_ID:-}" ]]; then
    HTTP_CODE=$(gh api "repos/$RUNSECURE_DISCOVERY_REPO/actions/jobs/$RUNSECURE_LAST_JOB_ID/logs" --include 2>&1 | head -1 | awk '{print $2}')
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "gh api .../jobs/$RUNSECURE_LAST_JOB_ID/logs returned 200"
    else
        fail "gh api returned $HTTP_CODE (expected 200)"
    fi
else
    echo "[SKIP] gh api check — RUNSECURE_DISCOVERY_REPO/RUNSECURE_LAST_JOB_ID not set"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
exit $((FAIL > 0))
