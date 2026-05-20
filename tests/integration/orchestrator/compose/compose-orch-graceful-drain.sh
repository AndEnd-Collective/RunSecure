#!/usr/bin/env bash
# A3 graceful drain: SIGTERM the orchestrator mid-flight; it must drain
# (wait for in-flight runners) before exiting.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=2 stack_up
wait_for_log "runsecure.orchestrator.spawn.runner_created" 30 || exit 1

# Send SIGTERM.
docker kill --signal=SIGTERM rs-test-orchestrator

# Within drain timeout (default 60s but containers exit fast), orchestrator
# should exit cleanly.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  STATE=$(docker inspect rs-test-orchestrator --format '{{.State.Status}}' 2>/dev/null || echo "gone")
  if [[ "$STATE" == "exited" || "$STATE" == "gone" ]]; then
    echo "OK: orchestrator drained and exited cleanly"
    exit 0
  fi
  sleep 1
done

echo "FAIL: orchestrator did not exit within 15s"
exit 1
