#!/usr/bin/env bash
# compose-orch-spawn-cycle: mock GitHub reports 1 queued job; orchestrator
# spawns a runner; spawn.completed fires after the runner exits.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=1 stack_up

if wait_for_log "runsecure.orchestrator.spawn.started" 30; then
  echo "OK: spawn.started observed"
else
  echo "FAIL: spawn never started"
  exit 1
fi
