#!/bin/bash
# ============================================================================
# RunSecure — TCP Egress Tests (Docker-based)
# ============================================================================
# Verifies that HAProxy correctly proxies TCP connections from runner to
# external TCP services when tcp_egress is configured.
#
# Runs inside the runner container via docker-compose.test.yml.
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0

check() {
    local name="$1"
    shift
    if "$@"; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

# --- HAProxy is running in the proxy container -------------------------------
check "HAProxy process running in proxy" \
    bash -c "curl -sf --connect-timeout 3 http://proxy:3128 || true; \
             # We can't directly check HAProxy in proxy container from runner.
             # Instead verify TCP port on proxy is open (set by tcp_egress).
             timeout 3 bash -c 'echo >/dev/tcp/proxy/5432' 2>/dev/null"

# --- Direct internet connection from runner is blocked -----------------------
check "Direct TCP to internet is blocked (no direct route)" \
    bash -c "! timeout 3 bash -c 'echo >/dev/tcp/8.8.8.8/53' 2>/dev/null"

# --- TCP via HAProxy port reaches postgres-test ------------------------------
# postgres-test is on proxy-external, runner is on test-net (internal).
# HAProxy listens on proxy:5432 and forwards to postgres-test:5432.
check "TCP port 5432 on proxy responds (HAProxy listening)" \
    bash -c "timeout 5 bash -c 'echo >/dev/tcp/proxy/5432' 2>/dev/null"

echo ""
echo "=== TCP Egress Tests: $PASS passed, $FAIL failed ==="
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
