#!/usr/bin/env bash
# Network isolation property — the LOAD-BEARING test of spec §4.3.
#
# Empirically verifies: a runner container cannot reach the internet
# by any path that bypasses the per-spawn proxy stack. We:
#   1. Start the test stack.
#   2. Trigger a spawn (mock GitHub returns 1 queued job).
#   3. Wait for the runner container to come up.
#   4. exec into it (test-harness only) and run forbidden network ops.
#   5. Each must FAIL; if any succeeds, the test fails.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=1 stack_up
wait_for_log "runsecure.orchestrator.spawn.runner_created" 30 || exit 1

# Find the spawned runner container (label runsecure.role=runner).
RUNNER=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  RUNNER=$(docker ps --filter "label=runsecure.role=runner" --format '{{.ID}}' | head -1)
  if [[ -n "$RUNNER" ]]; then break; fi
  sleep 1
done

if [[ -z "$RUNNER" ]]; then
  echo "FAIL: no runner container found after spawn"
  exit 1
fi

assert_fails() {
  local cmd="$*"
  if docker exec "$RUNNER" sh -c "$cmd" >/dev/null 2>&1; then
    echo "FAIL: expected failure for: $cmd"
    exit 1
  fi
  echo "OK: blocked: $cmd"
}

echo "=== Direct egress to evil.example.com must be blocked (no proxy) ==="
assert_fails "env -u HTTP_PROXY -u HTTPS_PROXY curl --max-time 5 -sf https://evil.example.com"

echo "=== Direct DNS to public resolver must fail ==="
assert_fails "nc -z -w 3 8.8.8.8 53"

echo "=== Raw socket / ICMP must fail (no NET_RAW capability) ==="
assert_fails "ping -c 1 -W 2 1.1.1.1"

echo "=== Routing modification must fail (no NET_ADMIN capability) ==="
assert_fails "ip route add default via 1.1.1.1"

echo "PASS: network-isolation-property holds"
