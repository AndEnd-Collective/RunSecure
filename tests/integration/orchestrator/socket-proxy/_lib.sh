#!/usr/bin/env bash
# Shared helpers for socket-proxy integration tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

start_proxy() {
  local cname="$1"
  docker rm -f "$cname" 2>/dev/null || true
  docker run -d --rm --name "$cname" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    -e RUNSECURE_DOCKER_SOCK=/var/run/docker.sock \
    -e RUNSECURE_LISTEN_ADDR=:2375 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -p 127.0.0.1:12375:2375 \
    runsecure-socket-proxy:local >/dev/null

  # Wait for listener to come up.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf http://127.0.0.1:12375/v1.43/info -o /dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "socket-proxy did not start"
  return 1
}

stop_proxy() {
  local cname="$1"
  docker rm -f "$cname" 2>/dev/null || true
}

# probe <method> <path> [body] → echoes HTTP status.
probe() {
  local method="$1"; local path="$2"; local body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sk -o /dev/null -w "%{http_code}" -X "$method" \
      -H "Content-Type: application/json" \
      --data-raw "$body" "http://127.0.0.1:12375$path"
  else
    curl -sk -o /dev/null -w "%{http_code}" -X "$method" \
      "http://127.0.0.1:12375$path"
  fi
}
