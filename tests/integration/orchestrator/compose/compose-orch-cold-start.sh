#!/usr/bin/env bash
# Cold-start recovery: spawn N runners, kill the orchestrator mid-flight,
# restart, then prove the old JIT registrations and containers are cleaned
# instead of being adopted as capacity that can never be released.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=2 stack_up
wait_for_log "runsecure.orchestrator.spawn.runner_created" 30 || exit 1

OLD_IDS=$(docker ps --filter "label=runsecure.scope=test" \
  --filter "label=runsecure.spawn_id" --format '{{.ID}}')
if [[ -z "${OLD_IDS}" ]]; then
  echo "FAIL: no managed spawn containers existed before restart"
  exit 1
fi

# Kill orchestrator container; restart it.
pname="$(project_name)"
$DC -f "${COMPOSE_FILE}" -p "${pname}" kill orchestrator
$DC -f "${COMPOSE_FILE}" -p "${pname}" start orchestrator

# Every pre-restart container must disappear. New demand may create replacement
# containers, so compare exact IDs rather than asserting a global count.
elapsed=0
while (( elapsed < 30 )); do
  stale=0
  for id in ${OLD_IDS}; do
    if docker inspect "${id}" >/dev/null 2>&1; then
      stale=1
      break
    fi
  done
  if (( stale == 0 )); then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if (( stale != 0 )); then
  echo "FAIL: a recovered container survived cold-start cleanup"
  exit 1
fi

if ! $DC -f "${COMPOSE_FILE}" -p "${pname}" logs mock-github 2>&1 \
    | grep -q "deleted runner registration"; then
  echo "FAIL: no recovered JIT registration was deregistered"
  exit 1
fi

SNAP=$(curl -sf http://127.0.0.1:18081/state/snapshot || echo '{}')
echo "Snapshot: $SNAP"
echo "OK: orchestrator cleaned recovered registrations/containers and restarted"
