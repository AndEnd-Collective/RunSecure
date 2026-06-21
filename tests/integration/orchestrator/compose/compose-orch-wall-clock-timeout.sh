#!/usr/bin/env bash
# A2 wall-clock timeout: with runner.yml orchestrator.timeout_seconds set
# very low and a runner image that won't claim a job (no real job runs),
# the spawn must be force-torn-down past the timeout.
#
# Note: the Compose backend doesn't ship a real "hang forever" runner image. This test
# uses the mock-github stub to advertise queued jobs that never come; the
# spawned actions/runner container will idle and the test asserts the
# spawn.timeout_forced_teardown event fires before the runner naturally
# exits. With timeout_seconds=10 and a 5-min runner idle ceiling, this
# bounds the test wall-clock under ~30s.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

# Override the runner.yml timeout to a tiny value.
ensure_testdata
sed -i.bak 's/timeout_seconds: 60/timeout_seconds: 10/' "${TESTDATA_DIR}/proj/.github/runner.yml" 2>/dev/null || true

MOCK_QUEUED_OWNER_REPO=1 stack_up

if wait_for_log "runsecure.orchestrator.spawn.timeout_forced_teardown" 45; then
  echo "OK: wall-clock timeout fired"
else
  echo "FAIL: timeout event never observed"
  exit 1
fi

# Restore the testdata for subsequent tests.
mv "${TESTDATA_DIR}/proj/.github/runner.yml.bak" "${TESTDATA_DIR}/proj/.github/runner.yml" 2>/dev/null || true
