#!/usr/bin/env bash
# Verify that a spawn request with disallowed HostConfig is refused.
# We can't easily inject a bad request from the orchestrator side, so this
# test verifies the orchestrator's NORMAL spawn doesn't trip any 403 — and
# probes the socket-proxy directly with a privileged request that MUST fail.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=0 stack_up

# Probe the socket-proxy directly (it's on test-net so we can reach it from
# the mock-github container via docker exec).
RESP=$(docker exec rs-test-mock-github sh -c '\
  wget -qO- --header "Content-Type: application/json" \
    --post-data "{\"Image\":\"bad\",\"User\":\"\",\"HostConfig\":{\"Privileged\":true}}" \
    http://socket-proxy:2375/v1.43/containers/create 2>&1 || true')

if echo "$RESP" | grep -q "403"; then
  echo "OK: socket-proxy refused Privileged:true"
else
  echo "FAIL: expected 403, got: $RESP"
  exit 1
fi
