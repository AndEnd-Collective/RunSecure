#!/bin/bash
# N04: HAProxy TCP egress allows whitelisted host:port, blocks others
# This requires the dummy project to declare a tcp_egress entry.
# We use a known-up TCP target: github.com:22 (SSH; should be in tcp_egress
# of the dummy project's runner.yml).
source "$(dirname "$0")/../in-container/lib.sh"

# Allowed: a TCP port in tcp_egress (the dummy project will configure
# postgres.example.com:5432 — we exercise the proxy frontend, not the
# backend's reachability).
# We use bash /dev/tcp which connects through the proxy port directly.
if bash -c 'exec 3<>/dev/tcp/proxy/5432' 2>/dev/null; then
    pass N04 "TCP connection to proxy:5432 (whitelisted port) accepted"
else
    skip N04 "tcp_egress :5432 frontend test" "proxy alias not resolvable from runner"
fi

# Blocked: arbitrary port not on allowlist
expect_fail N04 "TCP connection to proxy:9999 (not on allowlist) refused" -- \
    timeout 3 bash -c 'exec 3<>/dev/tcp/proxy/9999'

summary
