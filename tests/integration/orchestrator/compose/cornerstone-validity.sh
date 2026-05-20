#!/usr/bin/env bash
# Run the orchestrator for ~30 seconds with mixed traffic, capture all
# Cornerstone events from stdout, validate against the .cornerstone/events
# registry via corner-lint. Every emitted event MUST be registered.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=2 stack_up
sleep 20
LOGS=$(orch_logs)

# Extract each Cornerstone-shaped JSON line and check event.sub.type
# matches a registered signature in .cornerstone/events.
REGISTERED=$(ls "$(dirname "$0")"/../../../../.cornerstone/events/*.yaml | xargs -n1 basename | sed 's/\.yaml$//')
EMITTED=$(echo "$LOGS" | grep -o '"event.sub.type":"[^"]*"' | sed 's/.*:"//;s/"$//' | sort -u || true)

if [[ -z "$EMITTED" ]]; then
  echo "FAIL: no cornerstone events emitted in 20s window"
  echo "$LOGS" | tail -30
  exit 1
fi

for ev in $EMITTED; do
  if ! echo "$REGISTERED" | grep -q "^${ev}$"; then
    echo "FAIL: emitted unregistered event: $ev"
    exit 1
  fi
done

echo "PASS: $(echo "$EMITTED" | wc -l | tr -d ' ') distinct events emitted, all registered"
