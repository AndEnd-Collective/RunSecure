#!/usr/bin/env bash
# compose-egress-attacker: five attacker scenarios that must all be BLOCKED.
#
# A1: Cloud metadata via proxy (169.254.169.254) — Squid blocks private IPs via
#     an explicit "http_access deny rs_private_dst" ACL placed before the domain
#     allowlist. This covers DNS-rebinding: even an allowed hostname that
#     resolves to a private IP will be denied based on the resolved destination.
#
# A2: Direct-to-IP bypass (curl 1.1.1.1 without proxy) — asserts NETWORK
#     ISOLATION (topology), not proxy policy. The runner container is attached
#     only to the internal network and has no route to the internet. This test
#     would pass even if the proxy were misconfigured, because the block comes
#     from Docker network topology, not from any proxy rule.
#
# A3: Runner reaching test-backend on spawn-egress network by name — asserts
#     NETWORK ISOLATION (topology). The runner is internal-only and cannot reach
#     spawn-egress hosts by name or address. This would pass even if the proxy
#     allowed all destinations.
#
# A4: Runner reaching socket-proxy:2375 — asserts NETWORK ISOLATION (topology).
#     The socket-proxy is on the compose test-net, not the internal network.
#     This would pass even if the proxy were misconfigured.
#
# A5: CONNECT to port 22 on allowed domain — Squid denies non-443 CONNECT.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap teardown_real_proxy_stack EXIT

setup_real_proxy_stack

sleep 3

PASS=0
FAIL=0

assert_blocked() {
  local label="$1"
  shift
  if docker exec "${EGRESS_RUNNER}" sh -c "$*" >/dev/null 2>&1; then
    echo "FAIL [${label}]: expected block but command succeeded"
    FAIL=$((FAIL + 1))
  else
    echo "OK: blocked [${label}]"
    PASS=$((PASS + 1))
  fi
}

echo "=== A1: cloud metadata via proxy must be blocked ==="
assert_blocked "A1-cloud-metadata" \
  'curl -sf --max-time 5 -x http://proxy:3128 http://169.254.169.254/latest/meta-data/'

echo "=== A2: direct-to-IP (1.1.1.1) without proxy must be blocked ==="
assert_blocked "A2-direct-to-ip" \
  'env -u HTTP_PROXY -u HTTPS_PROXY curl -sf --max-time 5 http://1.1.1.1/'

echo "=== A3: runner reaching test-backend on spawn-egress network must fail ==="
assert_blocked "A3-spawn-egress-reach" \
  'nc -z -w 3 test-backend 5432'

echo "=== A4: runner reaching socket-proxy:2375 must be refused ==="
# socket-proxy is on the compose test-net, not on the internal network.
assert_blocked "A4-socket-proxy-access" \
  'nc -z -w 3 socket-proxy 2375'

echo "=== A5: CONNECT to port 22 on allowed domain must be blocked by Squid ==="
assert_blocked "A5-connect-port-22" \
  'curl -sf --max-time 5 -x http://proxy:3128 --proxytunnel -p https://api.github.com:22'

echo ""
echo "Results: ${PASS} blocked (OK), ${FAIL} not blocked (FAIL)"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
echo "PASS: all attacker scenarios blocked"
