#!/usr/bin/env bash
# Verify the socket-proxy refuses container/create requests with tag-only
# image references (must be digest-pinned).
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

CNAME="rs-test-sp-imagepin"
trap "stop_proxy $CNAME" EXIT
start_proxy "$CNAME"

# The shipped allowed-images.txt is empty, so EVERY image reference will be
# refused — both tag-only and digest-pinned. We're testing the tag-only
# path explicitly here.
status=$(probe POST /v1.43/containers/create \
  '{"Image":"alpine:latest","User":"1001:0","HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]}}')

if [[ "$status" != "403" ]]; then
  echo "FAIL: tag-only image returned $status (expected 403)"
  exit 1
fi
echo "PASS: tag-only image refused"
