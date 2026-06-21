#!/usr/bin/env bash
# compose-egress-attach-deny.sh — Task 10 integration test.
#
# Proves end-to-end that the socket-proxy's egress-network isolation gate
# (Task 7) is active and correctly wired for the test stack:
#
#   NEGATIVE (attacker): container-create with runsecure.role=runner attaching
#     the egress network via NetworkingConfig.EndpointsConfig MUST be denied
#     with HTTP 403 + code=validation_failed.
#
#   NEGATIVE (NetworkMode bypass): same request with HostConfig.NetworkMode=<egress>
#     instead of EndpointsConfig MUST also be denied.
#
#   POSITIVE (proxy role): container-create with runsecure.role=proxy attaching
#     the egress network via EndpointsConfig must NOT be rejected on the
#     egress-gate ground (may be forwarded to dockerd and return a different
#     status, but must not return the egress-deny 403).
#
# Pattern mirrors compose-orch-socket-proxy-deny.sh: the test stack is brought
# up via stack_up, then curl is driven from a throwaway alpine container on
# the test network to reach socket-proxy:2375 directly.
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

trap stack_down EXIT

MOCK_QUEUED_OWNER_REPO=0 stack_up

# The socket-proxy is configured with
#   RUNSECURE_EGRESS_NETWORK="${RUNSECURE_EGRESS_NETWORK:-runsecure-egress}"
# (see docker-compose.test.yml).  Use the same default here.
EGRESS_NET="${RUNSECURE_EGRESS_NETWORK:-runsecure-egress}"
NETNAME="rs-test-$(basename "$0" .sh)_test-net"

# IMAGE must be an entry in the allowlist that socket-proxy loads.  The
# allowlist is written by ensure_test_allowlist() (called inside stack_up via
# ensure_testdata) and stored in testdata/allowed-images.txt.  We read it back
# so this script stays in sync even if the digest changes between runs.
ALLOWLIST_FILE="${SCRIPT_DIR}/testdata/allowed-images.txt"
# Extract the first non-comment, non-empty line.
ALLOWLISTED_IMAGE=$(grep -v '^\s*#' "${ALLOWLIST_FILE}" | grep -v '^\s*$' | head -1)

if [[ -z "${ALLOWLISTED_IMAGE}" ]]; then
  echo "FATAL: could not read allowlist image from ${ALLOWLIST_FILE}" >&2
  exit 1
fi

echo "Using allowlisted image: ${ALLOWLISTED_IMAGE}"
echo "Testing egress gate on network: ${EGRESS_NET}"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helper: POST body builder (here-doc to avoid quoting issues in --data-raw).
# We use printf to avoid issues with embedded single-quotes in image refs.
# ---------------------------------------------------------------------------

# curl_to_proxy executes a POST to socket-proxy:2375/v1.44/containers/create
# from a throwaway curlimages/curl container on the test network.
# Prints the HTTP status code on stdout.
curl_to_proxy() {
  local body="$1"
  docker run --rm --network "${NETNAME}" curlimages/curl:8.10.1 \
    -sk -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    --data-raw "${body}" \
    "http://socket-proxy:2375/v1.44/containers/create" 2>&1 | tail -1
}

# curl_to_proxy_body prints the full response body.
curl_to_proxy_body() {
  local body="$1"
  docker run --rm --network "${NETNAME}" curlimages/curl:8.10.1 \
    -sk -X POST \
    -H "Content-Type: application/json" \
    --data-raw "${body}" \
    "http://socket-proxy:2375/v1.44/containers/create" 2>&1
}

# A minimal body that passes ALL checks except the egress gate:
#   - Image is in the allowlist
#   - User is non-root
#   - HostConfig satisfies all hardening rules
# We then append NetworkingConfig to trigger the gate.
VALID_HC='"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]}'

# ---------------------------------------------------------------------------
# N1: runner role + EndpointsConfig attach → MUST be denied (403, validation_failed)
# ---------------------------------------------------------------------------
echo ""
echo "=== N1: runner role + EndpointsConfig attach → must be denied ==="

N1_BODY=$(printf '{"Image":"%s","User":"1001:0","Labels":{"runsecure.role":"runner"},%s,"NetworkingConfig":{"EndpointsConfig":{"%s":{}}}}' \
  "${ALLOWLISTED_IMAGE}" "${VALID_HC}" "${EGRESS_NET}")

N1_STATUS=$(curl_to_proxy "${N1_BODY}")
N1_BODY_RESP=$(curl_to_proxy_body "${N1_BODY}")

echo "  Status: ${N1_STATUS}"
echo "  Body:   ${N1_BODY_RESP}"

if [[ "${N1_STATUS}" == "403" ]]; then
  # Verify the code field is validation_failed (not route_not_allowed or similar).
  if echo "${N1_BODY_RESP}" | grep -q '"validation_failed"'; then
    echo "OK [N1]: runner→egress denied with 403 + validation_failed"
    PASS=$((PASS + 1))
  else
    echo "FAIL [N1]: got 403 but code is not validation_failed (body: ${N1_BODY_RESP})"
    FAIL=$((FAIL + 1))
  fi
else
  echo "FAIL [N1]: expected 403, got ${N1_STATUS}"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# N2: runner role + NetworkMode bypass → MUST be denied (403, validation_failed)
# ---------------------------------------------------------------------------
echo ""
echo "=== N2: runner role + NetworkMode=${EGRESS_NET} → must be denied ==="

N2_BODY=$(printf '{"Image":"%s","User":"1001:0","Labels":{"runsecure.role":"runner"},"HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"NetworkMode":"%s"}}' \
  "${ALLOWLISTED_IMAGE}" "${EGRESS_NET}")

N2_STATUS=$(curl_to_proxy "${N2_BODY}")
N2_BODY_RESP=$(curl_to_proxy_body "${N2_BODY}")

echo "  Status: ${N2_STATUS}"
echo "  Body:   ${N2_BODY_RESP}"

if [[ "${N2_STATUS}" == "403" ]]; then
  if echo "${N2_BODY_RESP}" | grep -q '"validation_failed"'; then
    echo "OK [N2]: runner+NetworkMode→egress denied with 403 + validation_failed"
    PASS=$((PASS + 1))
  else
    echo "FAIL [N2]: got 403 but code is not validation_failed (body: ${N2_BODY_RESP})"
    FAIL=$((FAIL + 1))
  fi
else
  echo "FAIL [N2]: expected 403, got ${N2_STATUS}"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# N3: unlabeled container (no role label) + EndpointsConfig attach → MUST also be denied
# ---------------------------------------------------------------------------
echo ""
echo "=== N3: no role label + EndpointsConfig attach → must be denied ==="

N3_BODY=$(printf '{"Image":"%s","User":"1001:0",%s,"NetworkingConfig":{"EndpointsConfig":{"%s":{}}}}' \
  "${ALLOWLISTED_IMAGE}" "${VALID_HC}" "${EGRESS_NET}")

N3_STATUS=$(curl_to_proxy "${N3_BODY}")
N3_BODY_RESP=$(curl_to_proxy_body "${N3_BODY}")

echo "  Status: ${N3_STATUS}"
echo "  Body:   ${N3_BODY_RESP}"

if [[ "${N3_STATUS}" == "403" ]]; then
  if echo "${N3_BODY_RESP}" | grep -q '"validation_failed"'; then
    echo "OK [N3]: unlabeled→egress denied with 403 + validation_failed"
    PASS=$((PASS + 1))
  else
    echo "FAIL [N3]: got 403 but code is not validation_failed (body: ${N3_BODY_RESP})"
    FAIL=$((FAIL + 1))
  fi
else
  echo "FAIL [N3]: expected 403, got ${N3_STATUS}"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# P1: proxy role + EndpointsConfig attach → must NOT be rejected on egress-gate grounds.
# The request is forwarded to dockerd, which may return its own error (e.g.
# 409 or 500 because no such network exists inside the test environment), but
# it must NOT return a 403 with code=validation_failed.
# ---------------------------------------------------------------------------
echo ""
echo "=== P1: proxy role + EndpointsConfig attach → must NOT trigger egress-deny ==="

P1_BODY=$(printf '{"Image":"%s","User":"1001:0","Labels":{"runsecure.role":"proxy"},%s,"NetworkingConfig":{"EndpointsConfig":{"%s":{}}}}' \
  "${ALLOWLISTED_IMAGE}" "${VALID_HC}" "${EGRESS_NET}")

P1_STATUS=$(curl_to_proxy "${P1_BODY}")
P1_BODY_RESP=$(curl_to_proxy_body "${P1_BODY}")

echo "  Status: ${P1_STATUS}"
echo "  Body:   ${P1_BODY_RESP}"

# The egress gate must NOT produce 403+validation_failed for a proxy-role request.
# (Other non-403 responses from dockerd are acceptable; 403 with a DIFFERENT code
# such as route_not_allowed is also unrelated to the egress gate.)
if [[ "${P1_STATUS}" == "403" ]] && echo "${P1_BODY_RESP}" | grep -q '"validation_failed"'; then
  # Only fail if the detail actually mentions the egress denial.
  if echo "${P1_BODY_RESP}" | grep -q 'egress'; then
    echo "FAIL [P1]: proxy role was rejected by egress gate (status=${P1_STATUS}, body=${P1_BODY_RESP})"
    FAIL=$((FAIL + 1))
  else
    echo "OK [P1]: proxy role returned validation_failed but NOT for egress gate (body: ${P1_BODY_RESP})"
    PASS=$((PASS + 1))
  fi
else
  echo "OK [P1]: proxy role not denied by egress gate (status=${P1_STATUS})"
  PASS=$((PASS + 1))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -gt 0 ]]; then
  echo "FAIL: egress-attach isolation gate not correctly enforced"
  exit 1
fi
echo "PASS: egress-attach isolation gate correctly enforced end-to-end"
