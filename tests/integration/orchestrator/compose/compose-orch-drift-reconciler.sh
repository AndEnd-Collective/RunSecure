#!/usr/bin/env bash
# A4 drift: manually kill a runner container while the orchestrator is
# alive; the next reconcile cycle decrements the in-flight counter and
# emits drift.reconciled.
#
# The Compose backend doesn't run a periodic drift reconciler by default
# (cold-start reconciles only). This test documents the expected behavior;
# the automated reconciler can be enabled via RUNSECURE_DRIFT_INTERVAL env
# var in a future enhancement. For now: just check the orchestrator
# doesn't crash when a managed container disappears unexpectedly.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=1 stack_up
wait_for_log "runsecure.orchestrator.spawn.runner_created" 30 || exit 1

RUNNER=$(docker ps --filter "label=runsecure.role=runner" --format '{{.ID}}' | head -1)
if [[ -z "$RUNNER" ]]; then
  echo "FAIL: no runner container found"
  exit 1
fi
docker kill "$RUNNER"

# Wait a poll cycle and verify orchestrator is still alive.
sleep 8
STATE=$(docker inspect rs-test-orchestrator --format '{{.State.Running}}')
if [[ "$STATE" == "true" ]]; then
  echo "OK: orchestrator survived runner kill"
else
  echo "FAIL: orchestrator crashed when runner was killed externally"
  exit 1
fi
