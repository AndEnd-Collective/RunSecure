#!/usr/bin/env bash
# Circuit breaker: mock-github returns 422 (JIT fail) repeatedly. After 5
# consecutive failures, breaker.opened fires; subsequent polls skip the repo.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

# Queue jobs but make every JIT generation fail.
MOCK_QUEUED_OWNER_REPO=10 MOCK_JIT_FAIL=1 stack_up

# Each poll tick (5s) attempts up to 2 spawns (repo cap). With 5-failure
# threshold, breaker should open within ~3 poll cycles.
if wait_for_log "runsecure.orchestrator.breaker.opened" 45; then
  echo "OK: breaker opened after consecutive JIT failures"
else
  echo "FAIL: breaker never opened"
  exit 1
fi
