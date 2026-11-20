#!/usr/bin/env bash
# Verify that a spawn request with disallowed HostConfig is refused.
# We can't easily inject a bad request from the orchestrator side, so this
# test verifies the orchestrator's NORMAL spawn doesn't trip any 403 — and
# probes the socket-proxy directly with a privileged request that MUST fail.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=0 stack_up

# Probe the socket-proxy directly from a throwaway alpine container on the
# test network (mock-github is distroless — no curl/wget). Body has
# Privileged:true which the socket-proxy must refuse with 403.
NETNAME="rs-test-$(basename $0 .sh)_test-net"
STATUS=$(docker run --rm --network "$NETNAME" curlimages/curl:8.10.1 \
  -sk -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  --data-raw '{"Image":"bad","User":"","HostConfig":{"Privileged":true}}' \
  http://socket-proxy:2375/v1.44/containers/create 2>&1 | tail -1)

if [[ "$STATUS" == "403" ]]; then
  echo "OK: socket-proxy refused Privileged:true (status $STATUS)"
else
  echo "FAIL: expected 403, got: $STATUS"
  exit 1
fi

# A request that passes every other HostConfig gate but asks for Docker's
# built-in bridge must also be refused: that network is NAT-routed to the
# internet, so a container on it never passes through the egress proxy.
# The response body is checked as well as the status, to prove it is the
# NetworkMode gate that fired and not an earlier one.
for MODE in bridge default ""; do
  BODY=$(docker run --rm --network "$NETNAME" curlimages/curl:8.10.1 \
    -sk -w '\n%{http_code}' -X POST \
    -H "Content-Type: application/json" \
    --data-raw "{\"Image\":\"bad\",\"User\":\"1001:0\",\"HostConfig\":{\"CapDrop\":[\"ALL\"],\"SecurityOpt\":[\"no-new-privileges:true\"],\"NetworkMode\":\"${MODE}\"}}" \
    http://socket-proxy:2375/v1.44/containers/create 2>&1)
  STATUS=$(tail -1 <<<"$BODY")
  if [[ "$STATUS" == "403" ]] && grep -q "NetworkMode" <<<"$BODY"; then
    echo "OK: socket-proxy refused NetworkMode '${MODE}' (status $STATUS)"
  else
    echo "FAIL: expected 403 naming NetworkMode for mode '${MODE}', got: $BODY"
    exit 1
  fi
done
