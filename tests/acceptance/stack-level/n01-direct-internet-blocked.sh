#!/bin/bash
# N01: container has no direct internet route — must go through proxy
# Disable HTTP_PROXY env, attempt direct connection — should fail.
source "$(dirname "$0")/../in-container/lib.sh"

# Curl with --noproxy '*' bypasses HTTP_PROXY env. Without the proxy,
# the request must hit the runner-net (internal:true) and fail.
expect_fail N01 "direct curl bypassing proxy fails" -- \
    curl --noproxy '*' --max-time 5 --silent --fail https://github.com

# Same with explicit --proxy '' override
expect_fail N01 "curl --proxy '' fails" -- \
    curl --proxy '' --max-time 5 --silent --fail https://github.com

# Raw TCP via /dev/tcp (bash builtin) — no proxy in path
expect_fail N01 "raw TCP to github.com:443 fails (no internet route)" -- \
    bash -c 'exec 3<>/dev/tcp/github.com/443; echo "GET / HTTP/1.0" >&3'

summary
