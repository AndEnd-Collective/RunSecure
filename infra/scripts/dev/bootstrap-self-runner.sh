#!/bin/bash
# ============================================================================
# RunSecure — Bootstrap a self-hosted runner against THIS repo
# ============================================================================
# Convenience wrapper around infra/scripts/run.sh with the right project
# + repo + sensible max-jobs default for self-CI (the dogfood.yml +
# lints-on-self workflow path).
#
# When to use:
#   You opened a PR and the `lints-on-self` check is pending. That check
#   targets the [self-hosted, Linux, ARM64, container] label set, which
#   needs a RunSecure runner online. Run this once to drain the queue,
#   it'll exit after MAX_JOBS jobs.
#
# Usage:
#   ./infra/scripts/dev/bootstrap-self-runner.sh           # default 5 jobs
#   ./infra/scripts/dev/bootstrap-self-runner.sh 20        # override count
#   MAX_JOBS=100 ./infra/scripts/dev/bootstrap-self-runner.sh   # via env
#
# Logs to _orchestrator-logs/run.log (gitignored). PID stored in
# _orchestrator-logs/orch.pid for clean shutdown via:
#   kill "$(cat _orchestrator-logs/orch.pid)"
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

MAX_JOBS="${1:-${MAX_JOBS:-5}}"
LOG_DIR="$REPO_ROOT/_orchestrator-logs"
mkdir -p "$LOG_DIR"

# Sanity checks before fork
if ! [ -f .github/runner.yml ]; then
    echo "[bootstrap] ERROR: .github/runner.yml not found at repo root" >&2
    echo "[bootstrap] are you on a branch that has the self-CI config?" >&2
    exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
    echo "[bootstrap] ERROR: gh CLI not on PATH" >&2; exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
    echo "[bootstrap] ERROR: gh CLI not authenticated — run 'gh auth login'" >&2; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "[bootstrap] ERROR: Docker daemon not reachable — start Colima/Docker Desktop" >&2; exit 1
fi

# How many dogfood runs are queued right now?
QUEUED=$(gh api 'repos/AndEnd-Collective/RunSecure/actions/runs?status=queued&per_page=20' \
    --jq '[.workflow_runs[] | select(.name == "dogfood")] | length' 2>/dev/null || echo "?")
echo "[bootstrap] queued dogfood runs: $QUEUED   max-jobs: $MAX_JOBS"
echo "[bootstrap] log: $LOG_DIR/run.log"
echo "[bootstrap] starting orchestrator in background..."

./infra/scripts/run.sh \
    --project . \
    --repo AndEnd-Collective/RunSecure \
    --max-jobs "$MAX_JOBS" \
    > "$LOG_DIR/run.log" 2>&1 &
ORCH_PID=$!
echo "$ORCH_PID" > "$LOG_DIR/orch.pid"
echo "[bootstrap] orchestrator PID=$ORCH_PID"
echo ""
echo "Watch progress:"
echo "  tail -f $LOG_DIR/run.log"
echo ""
echo "Stop early:"
echo "  kill \$(cat $LOG_DIR/orch.pid)"
echo ""
echo "Will exit after $MAX_JOBS jobs OR when no jobs are queued for ~50 seconds."
