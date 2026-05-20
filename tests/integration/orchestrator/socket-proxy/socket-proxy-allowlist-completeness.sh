#!/usr/bin/env bash
# Verify the socket-proxy refuses every non-allowlisted endpoint with 403.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

CNAME="rs-test-sp-allowlist"
trap "stop_proxy $CNAME" EXIT
start_proxy "$CNAME"

# Each of these MUST be 403.
declare -A FORBIDDEN=(
  ["POST /v1.43/containers/abc/exec"]="POST /v1.43/containers/abc/exec"
  ["POST /v1.43/containers/abc/attach"]="POST /v1.43/containers/abc/attach"
  ["POST /v1.43/build"]="POST /v1.43/build"
  ["POST /v1.43/images/create"]="POST /v1.43/images/create"
  ["POST /v1.43/volumes/create"]="POST /v1.43/volumes/create"
  ["GET /v1.43/images/json"]="GET /v1.43/images/json"
  ["POST /v1.43/swarm/init"]="POST /v1.43/swarm/init"
  ["GET /v1.43/secrets"]="GET /v1.43/secrets"
)

for label in "${!FORBIDDEN[@]}"; do
  method="${FORBIDDEN[$label]%% *}"
  path="${FORBIDDEN[$label]#* }"
  status=$(probe "$method" "$path")
  if [[ "$status" != "403" ]]; then
    echo "FAIL: $label returned $status (expected 403)"
    exit 1
  fi
  echo "OK: $label → 403"
done

echo "PASS: all non-allowlisted endpoints refused"
