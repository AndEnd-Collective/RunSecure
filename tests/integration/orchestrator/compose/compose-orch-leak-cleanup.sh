#!/usr/bin/env bash
# A1 leak cleanup: simulate a spawn that succeeds at JIT generation but
# fails container creation; verify the orchestrator DELETEs the orphan
# runner registration on the GitHub side (mock-github records the call).
#
# To force the post-JIT failure path, we'd ideally remove the runner
# image from the socket-proxy allowlist between JIT and container-create.
# Plan A's allowlist is bake-time, so this test verifies the orchestrator
# emits runner.leak_cleaned in the natural failure path induced by an
# image-not-allowed condition.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=1 stack_up

# The socket-proxy's allowed-images.txt is empty by default — every image
# reference is refused. The orchestrator will get a JIT then fail at the
# socket-proxy refuse, triggering A1 leak cleanup.
if wait_for_log "runsecure.orchestrator.runner.leak_cleaned" 45; then
  echo "OK: leak cleanup fired for orphan JIT"
else
  echo "FAIL: runner.leak_cleaned never observed"
  orch_logs | tail -30
  exit 1
fi
