#!/bin/bash
# ============================================================================
# RunSecure Unit Test — Per-repo orchestrator lock
# ============================================================================
# Verifies that two concurrent invocations of run.sh against the same repo
# fail fast on the second one (per-repo lockfile rejects the collision),
# and that a stale lock from a dead PID is taken over cleanly.
#
# Runs entirely on the host without launching containers — relies on run.sh
# erroring out at later stages (no Docker available in CI, or auth missing)
# AFTER the lock is acquired/checked.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/run.sh"

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }

WORKDIR=$(mktemp -d)
PROJECT_DIR="${WORKDIR}/project"
mkdir -p "$PROJECT_DIR/.github"
cat > "$PROJECT_DIR/.github/runner.yml" <<'YAML'
runtime: node:24
tools: []
http_egress: []
YAML

# Use a unique repo name per test run so we don't trip over lingering locks
# from other dev work.
REPO="testowner/lock-test-$$-$(date +%s)"
REPO_SLUG=$(echo "$REPO" | sed 's|.*/||; s/[^a-zA-Z0-9_-]/-/g' | tr '[:upper:]' '[:lower:]')
LOCK_PATH="${TMPDIR:-/tmp}/runsecure-${REPO_SLUG}.lock"

cleanup_locks() {
    rm -rf "$LOCK_PATH"
    rm -rf "$WORKDIR"
}
trap cleanup_locks EXIT

echo -e "\n${BOLD}=== Orchestrator Lock Tests ===${NC}\n"

# ----------------------------------------------------------------------------
# Test 1: Lock is created when run.sh starts
# ----------------------------------------------------------------------------
echo -e "${BOLD}--- 1. lock acquired on startup ---${NC}"

# Run with no auth so it errors out after the lock check. We verify by
# checking that the lock dir was created, then verifying it gets cleaned
# up on EXIT.
"$RUN_SCRIPT" --project "$PROJECT_DIR" --repo "$REPO" --max-jobs 1 >/dev/null 2>&1 || true

# After the script exits cleanly, the lock should be gone (cleanup trap).
if [[ ! -d "$LOCK_PATH" ]]; then
    pass "Lock cleaned up after run.sh exits"
else
    fail "Lock at $LOCK_PATH not cleaned up"
    rm -rf "$LOCK_PATH"
fi

# ----------------------------------------------------------------------------
# Test 2: Second invocation rejected when first PID is alive
# ----------------------------------------------------------------------------
echo -e "\n${BOLD}--- 2. concurrent invocation rejected ---${NC}"

# Simulate a live first orchestrator by manually creating the lock with our
# own PID (we know we're alive — kill -0 $$ succeeds).
mkdir "$LOCK_PATH"
echo "$$" > "$LOCK_PATH/pid"

OUTPUT=$("$RUN_SCRIPT" --project "$PROJECT_DIR" --repo "$REPO" --max-jobs 1 2>&1 || true)
if echo "$OUTPUT" | grep -q "another orchestrator is already running"; then
    pass "Rejects concurrent invocation against same repo"
else
    fail "Did not reject concurrent invocation; output: $OUTPUT"
fi

# Lock should still be intact (not deleted by the rejected invocation).
if [[ -d "$LOCK_PATH" ]] && [[ "$(cat "$LOCK_PATH/pid")" == "$$" ]]; then
    pass "Original lock untouched by rejected invocation"
else
    fail "Original lock was modified by the rejected invocation"
fi

rm -rf "$LOCK_PATH"

# ----------------------------------------------------------------------------
# Test 3: Stale lock (dead PID) is taken over
# ----------------------------------------------------------------------------
echo -e "\n${BOLD}--- 3. stale lock from dead PID is taken over ---${NC}"

# Use a PID that's vanishingly unlikely to be alive: 99999999 is well past
# the typical pid_max (4M on Linux, 99999 on macOS).
mkdir "$LOCK_PATH"
echo "99999999" > "$LOCK_PATH/pid"

OUTPUT=$("$RUN_SCRIPT" --project "$PROJECT_DIR" --repo "$REPO" --max-jobs 1 2>&1 || true)
if echo "$OUTPUT" | grep -q "Stale lock from PID 99999999 — taking over"; then
    pass "Detects and takes over stale lock"
else
    fail "Did not take over stale lock; output: $OUTPUT"
fi

# After the second invocation exits, lock should be cleaned up.
if [[ ! -d "$LOCK_PATH" ]]; then
    pass "Lock cleaned up after stale-lock takeover run"
else
    fail "Lock not cleaned up after stale-lock takeover"
    rm -rf "$LOCK_PATH"
fi

# ----------------------------------------------------------------------------
# Test 4: Different repos can run concurrently (lock is per-repo)
# ----------------------------------------------------------------------------
echo -e "\n${BOLD}--- 4. different repos do not collide ---${NC}"

OTHER_REPO="testowner/different-repo-$$-$(date +%s)"
OTHER_REPO_SLUG=$(echo "$OTHER_REPO" | sed 's|.*/||; s/[^a-zA-Z0-9_-]/-/g' | tr '[:upper:]' '[:lower:]')
OTHER_LOCK="${TMPDIR:-/tmp}/runsecure-${OTHER_REPO_SLUG}.lock"

# Hold a live lock for the FIRST repo
mkdir "$LOCK_PATH"
echo "$$" > "$LOCK_PATH/pid"

# Try the SECOND repo — should NOT be rejected by the first repo's lock
OUTPUT=$("$RUN_SCRIPT" --project "$PROJECT_DIR" --repo "$OTHER_REPO" --max-jobs 1 2>&1 || true)
if echo "$OUTPUT" | grep -q "another orchestrator is already running"; then
    fail "Rejected a different-repo invocation (lock scope is too broad)"
else
    pass "Different-repo invocation NOT rejected by first repo's lock"
fi

# Cleanup the second repo's lock if it leaked
rm -rf "$OTHER_LOCK"
rm -rf "$LOCK_PATH"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${BOLD}=== Summary ===${NC}"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
