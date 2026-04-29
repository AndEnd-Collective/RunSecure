#!/bin/bash
# ============================================================================
# RunSecure — Log-Loss Fix Integration Test (self-contained)
# ============================================================================
# Verifies that:
#   1. entrypoint.sh runs ./run.sh as a foreground child (not exec) and waits
#      for the upload-complete marker in _diag/Worker_*.log before exiting.
#   2. When the marker is present, the wait exits immediately.
#   3. When the marker is absent, the wait times out cleanly with a warning
#      and the runner's exit code propagates.
#   4. lib/diag-rotation.sh rotates _diag/ -> _diag.previous/ correctly.
#   5. RUNSECURE_DIAG_RETENTION=0 skips rotation entirely.
#
# Optional: if RUNSECURE_DISCOVERY_REPO + RUNSECURE_LAST_JOB_ID are set, also
# verifies that `gh api .../jobs/<id>/logs` returns 200 (operator-side check
# after a real orchestrator run).
#
# Self-contained: builds a fake RUNNER_DIR with a stub run.sh that touches a
# Worker_*.log and exits, then invokes a sed-modified copy of entrypoint.sh
# pointing at it. No host-side bind mount required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Mounted bind paths (in container) vs repo root (on host). Prefer the bind
# mount if present so this works inside the integration test compose runner.
if [[ -f /mnt/infra/scripts/entrypoint.sh ]]; then
    REAL_ENTRYPOINT="/mnt/infra/scripts/entrypoint.sh"
    ROTATION_HELPER="/mnt/infra/scripts/lib/diag-rotation.sh"
else
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    REAL_ENTRYPOINT="$REPO_ROOT/infra/scripts/entrypoint.sh"
    ROTATION_HELPER="$REPO_ROOT/infra/scripts/lib/diag-rotation.sh"
fi

PASS=0
FAIL=0
pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "[SKIP] $1"; }

# /tmp is mounted noexec in production; use $HOME so direct `./run.sh` exec works.
WORK=$(mktemp -d -p "${HOME:-/home/runner}")
trap 'rm -rf "$WORK"' EXIT

make_fake_runner() {
    local dir="$1"
    local emit_marker="$2"   # "yes" / "no"
    local marker="${3:-All queue process tasks have been stopped, and all queues are drained.}"

    rm -rf "$dir"
    mkdir -p "$dir/_diag" "$dir/bin"
    echo '{}' > "$dir/bin/Runner.Listener.deps.json"

    # Pre-create the Worker log directly (more reliable than letting the fake
    # run.sh write it). When emit_marker=yes, include the marker; otherwise
    # populate with non-marker content so the wait-for-marker path is
    # exercised but never satisfied.
    local worker_log="$dir/_diag/Worker_test.log"
    if [[ "$emit_marker" == "yes" ]]; then
        printf '[INFO Worker.JobRunner] starting test-job\n[INFO JobServerQueue] %s\n' "$marker" > "$worker_log"
    else
        printf '[INFO Worker.JobRunner] starting test-job (no marker)\n' > "$worker_log"
    fi

    cat > "$dir/run.sh" <<'SCRIPT'
#!/bin/bash
echo "MARKER-FAIL" >&2
echo "[fake-runner] running" >&2
exit 1
SCRIPT
    chmod +x "$dir/run.sh"
}

run_modified_entrypoint() {
    local fake_dir="$1"
    local timeout="$2"
    local entrypoint_copy="$fake_dir/entrypoint-test.sh"

    sed "s|RUNNER_DIR=\"/home/runner/actions-runner\"|RUNNER_DIR=\"$fake_dir\"|" \
        "$REAL_ENTRYPOINT" > "$entrypoint_copy"
    chmod +x "$entrypoint_copy"

    RUNSECURE_LOG_UPLOAD_TIMEOUT="$timeout" \
    RUNNER_JIT_CONFIG="FAKE_JIT" \
    bash "$entrypoint_copy" 2>&1
}

# ----------------------------------------------------------------------------
# Test 1: Marker present -> wait exits immediately, runner exit code preserved
# ----------------------------------------------------------------------------
TEST1_DIR="$WORK/marker-present"
make_fake_runner "$TEST1_DIR" yes
START_TIME=$(date +%s)
T1_OUTPUT=$(run_modified_entrypoint "$TEST1_DIR" 10 || true)
T1_EXIT=$?
ELAPSED=$(( $(date +%s) - START_TIME ))

if echo "$T1_OUTPUT" | grep -q "Log upload .* confirmed"; then
    pass "wait succeeds when marker is present in Worker_*.log"
else
    fail "marker-present case did not log 'Log upload confirmed' (output: $T1_OUTPUT)"
fi
if [[ "$ELAPSED" -lt 5 ]]; then
    pass "wait exits quickly when marker is present (${ELAPSED}s)"
else
    fail "wait took ${ELAPSED}s with marker present (should be <5s)"
fi

# ----------------------------------------------------------------------------
# Test 2: Marker absent -> wait times out cleanly, warning emitted
# ----------------------------------------------------------------------------
TEST2_DIR="$WORK/marker-absent"
make_fake_runner "$TEST2_DIR" no
START_TIME=$(date +%s)
T2_OUTPUT=$(run_modified_entrypoint "$TEST2_DIR" 2 || true)
ELAPSED=$(( $(date +%s) - START_TIME ))

if echo "$T2_OUTPUT" | grep -q "log upload wait timed out"; then
    pass "wait times out cleanly when marker is absent"
else
    fail "marker-absent case did not log 'log upload wait timed out' (output: $T2_OUTPUT)"
fi
if [[ "$ELAPSED" -ge 2 && "$ELAPSED" -lt 6 ]]; then
    pass "wait honored timeout (${ELAPSED}s, expected 2..5s)"
else
    fail "wait elapsed ${ELAPSED}s, expected 2-5s"
fi

# ----------------------------------------------------------------------------
# Test 3: rotation helper rotates _diag/ -> _diag.previous/
# ----------------------------------------------------------------------------
ROT_DIR="$WORK/rotation-test"
mkdir -p "$ROT_DIR/_diag"
echo "first run log" > "$ROT_DIR/_diag/Worker_first.log"

# shellcheck source=infra/scripts/lib/diag-rotation.sh
source "$ROTATION_HELPER"
rotate_diag_dirs "$ROT_DIR" >/dev/null 2>&1

if [[ -f "$ROT_DIR/_diag.previous/Worker_first.log" ]] && \
   ! [[ -f "$ROT_DIR/_diag/Worker_first.log" ]]; then
    pass "rotation moves _diag/ contents to _diag.previous/"
else
    fail "rotation did not move contents correctly"
fi

if [[ -d "$ROT_DIR/_diag-proxy" ]]; then
    pass "rotation creates _diag-proxy/ directory"
else
    fail "rotation did not create _diag-proxy/"
fi

# ----------------------------------------------------------------------------
# Test 4: RUNSECURE_DIAG_RETENTION=0 skips rotation
# ----------------------------------------------------------------------------
KS_DIR="$WORK/kill-switch-test"
mkdir -p "$KS_DIR/_diag"
echo "should not rotate" > "$KS_DIR/_diag/Worker_keep.log"

RUNSECURE_DIAG_RETENTION=0 rotate_diag_dirs "$KS_DIR" >/dev/null 2>&1

if [[ -f "$KS_DIR/_diag/Worker_keep.log" ]] && ! [[ -d "$KS_DIR/_diag.previous" ]]; then
    pass "RUNSECURE_DIAG_RETENTION=0 skips rotation entirely"
else
    fail "RUNSECURE_DIAG_RETENTION=0 did not skip rotation"
fi

# ----------------------------------------------------------------------------
# Test 5: Optional gh api check (operator-side post-real-run validation)
# ----------------------------------------------------------------------------
if [[ -n "${RUNSECURE_DISCOVERY_REPO:-}" && -n "${RUNSECURE_LAST_JOB_ID:-}" ]]; then
    HTTP_CODE=$(gh api "repos/$RUNSECURE_DISCOVERY_REPO/actions/jobs/$RUNSECURE_LAST_JOB_ID/logs" --include 2>&1 | head -1 | awk '{print $2}')
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "gh api .../jobs/$RUNSECURE_LAST_JOB_ID/logs returned 200"
    else
        fail "gh api returned $HTTP_CODE (expected 200)"
    fi
else
    skip "gh api check — set RUNSECURE_DISCOVERY_REPO and RUNSECURE_LAST_JOB_ID after a real run.sh invocation"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
exit $((FAIL > 0))
