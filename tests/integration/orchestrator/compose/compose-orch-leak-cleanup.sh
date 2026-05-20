#!/usr/bin/env bash
# A1 leak cleanup: spawn succeeds at JIT generation but fails container
# creation; orchestrator DELETEs the orphan GitHub runner registration.
#
# With the bug #5 fix populating a test allowlist, we now have to force
# the post-JIT failure path manually — override the allowlist for THIS
# test only to be empty so socket-proxy refuses every containers/create.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

# Run ensure_testdata first (which populates the allowlist), then override.
ensure_testdata
echo "# Empty allowlist — forces socket_proxy_denied post-JIT (this test only)." \
  > "${TESTDATA_DIR}/allowed-images.txt"

MOCK_QUEUED_OWNER_REPO=1 stack_up

if wait_for_log "runsecure.orchestrator.runner.leak_cleaned" 45; then
  echo "OK: leak cleanup fired for orphan JIT"
else
  echo "FAIL: runner.leak_cleaned never observed"
  orch_logs | tail -30
  exit 1
fi
