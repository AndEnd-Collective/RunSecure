#!/usr/bin/env bash
# PAT rotation: replace the PAT secret file mid-flight; orchestrator
# reloads on next request (mtime-driven reload in github.Client).
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=0 stack_up
sleep 8 # let one poll tick happen with v1

# Rewrite the PAT (force mtime change).
chmod 600 "${TESTDATA_DIR}/pat"
echo "ghp_v2_rotated" > "${TESTDATA_DIR}/pat"
touch -m "${TESTDATA_DIR}/pat"
chmod 400 "${TESTDATA_DIR}/pat"

# Next poll cycle should use the new token transparently. We don't have a
# direct config.reloaded emit on PAT-rotation in Plan A (mtime reload is
# silent in github.Client). The test verifies the orchestrator continues
# to operate after rotation rather than asserting a specific event.
sleep 8
ORCH_RUNNING=$(docker inspect rs-test-orchestrator --format '{{.State.Running}}')
if [[ "$ORCH_RUNNING" == "true" ]]; then
  echo "OK: orchestrator continued running after PAT rotation"
else
  echo "FAIL: orchestrator died after PAT change"
  exit 1
fi
