#!/usr/bin/env bash
# compose-egress-http: real-proxy egress HTTP/HTTPS allow-path tests.
#
# Exercises the real runsecure-proxy:itest (squid+haproxy+dnsmasq) against
# actual HTTP/HTTPS egress rules, closing the coverage hole where the harness
# used an alpine sleep stub.
#
# Positive: runner reaches api.github.com via proxy (in squid allowlist).
# Negative: runner cannot reach example.com via proxy (not in allowlist).
#
# Containers are started directly (not via orchestrator spawn) so that the
# generated egress configs can be bind-mounted from host-accessible paths
# rather than the orchestrator's tmpfs. The egress filtering logic is identical
# to what the orchestrator wires at spawn time.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap teardown_real_proxy_stack EXIT

setup_real_proxy_stack

# Give squid a moment to finish initializing.
sleep 3

echo "=== HTTP positive: api.github.com must be reachable via proxy ==="
if docker exec "${EGRESS_RUNNER}" \
    sh -c 'curl -sf --max-time 15 -x http://proxy:3128 https://api.github.com/zen' \
    >/dev/null 2>&1; then
  echo "OK: api.github.com reachable via proxy"
else
  echo "FAIL: api.github.com unreachable via proxy (expected allow)"
  echo "--- squid log ---"
  docker exec "${REAL_PROXY_CONTAINER}" sh -c 'tail -20 /var/log/squid/access.log 2>/dev/null || echo "(no log)"' 2>&1 || true
  docker logs "${REAL_PROXY_CONTAINER}" 2>&1 | tail -20 || true
  exit 1
fi

echo "=== HTTP negative: example.com must be blocked by proxy ==="
if docker exec "${EGRESS_RUNNER}" \
    sh -c 'curl -sf --max-time 10 -x http://proxy:3128 https://example.com' \
    >/dev/null 2>&1; then
  echo "FAIL: example.com reachable via proxy (expected block)"
  exit 1
else
  echo "OK: example.com blocked by proxy"
fi

echo "PASS: egress-http checks passed"
