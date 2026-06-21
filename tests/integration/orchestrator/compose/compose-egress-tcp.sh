#!/usr/bin/env bash
# compose-egress-tcp: real-proxy egress TCP allow-path tests via HAProxy.
#
# The real runsecure-proxy:itest is configured with tcp_egress: [test-backend:5432].
# HAProxy listens on port 5432 inside the proxy container and forwards to
# test-backend:5432 on the spawn-egress network.
#
# Positive: nc -z -w8 proxy 5432  (HAProxy frontend open; test-backend echoes)
# Negative: nc -z -w3 proxy 6379  (no HAProxy frontend on 6379 — refused)
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap teardown_real_proxy_stack EXIT

setup_real_proxy_stack

# Give HAProxy a moment to start inside the proxy container.
sleep 5

echo "=== TCP positive: proxy:5432 (HAProxy -> test-backend:5432) must accept ==="
if docker exec "${EGRESS_RUNNER}" \
    sh -c 'nc -z -w 8 proxy 5432' \
    >/dev/null 2>&1; then
  echo "OK: TCP connection to proxy:5432 accepted (HAProxy forwarding works)"
else
  echo "FAIL: TCP connection to proxy:5432 refused"
  echo "--- proxy logs ---"
  docker logs "${REAL_PROXY_CONTAINER}" 2>&1 | tail -30 || true
  exit 1
fi

echo "=== TCP negative: proxy:6379 (no HAProxy frontend) must be refused ==="
if docker exec "${EGRESS_RUNNER}" \
    sh -c 'nc -z -w 3 proxy 6379' \
    >/dev/null 2>&1; then
  echo "FAIL: TCP connection to proxy:6379 accepted (expected refuse)"
  exit 1
else
  echo "OK: proxy:6379 refused (no HAProxy frontend for unlisted port)"
fi

echo "PASS: egress-tcp checks passed"
