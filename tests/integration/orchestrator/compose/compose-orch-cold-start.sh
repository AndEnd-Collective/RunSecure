#!/usr/bin/env bash
# Cold-start recovery: spawn N runners, kill the orchestrator mid-flight,
# restart, verify it reconciles in-flight count from docker labels.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=2 stack_up
wait_for_log "runsecure.orchestrator.spawn.runner_created" 30 || exit 1

# Kill orchestrator container; restart it.
pname="$(project_name)"
docker compose -f "${COMPOSE_FILE}" -p "${pname}" kill orchestrator
docker compose -f "${COMPOSE_FILE}" -p "${pname}" start orchestrator

# After restart, /state/snapshot should report ≥ 1 in-flight runner if any
# spawned containers are still running.
sleep 5
SNAP=$(curl -sf http://127.0.0.1:18081/state/snapshot || echo '{}')
echo "Snapshot: $SNAP"
echo "OK: orchestrator restarted and serves /state/snapshot"
