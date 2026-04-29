#!/bin/bash
# ============================================================================
# RunSecure — DNS Validation Tests (Docker-based)
# ============================================================================
# Verifies that dnsmasq in the proxy container correctly:
#   - Serves custom hosts file entries
#   - Applies whitelist filtering when configured
#   - Responds to queries from the runner
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

# --- dnsmasq responding to basic queries ------------------------------------
# When ENABLE_DNSMASQ=true, proxy listens on port 53.
# Runner DNS is set to proxy (10.11.12.13) via runtime-compose.yml.

# Check that we can resolve github.com (should be in servers upstream)
check "DNS resolves github.com" \
    bash -c "getent hosts github.com 2>/dev/null | grep -q '\.'"

# Check custom hosts file entry resolves
check "DNS resolves test-service.internal.example.com (from hosts file)" \
    bash -c "getent hosts test-service.internal.example.com 2>/dev/null | grep -q '192.0.2.10'"

# Verify runner is using proxy as DNS resolver
check "Runner DNS points to proxy" \
    bash -c "cat /etc/resolv.conf | grep -qE '10\.11\.12\.13'"

# --- whitelist enforcement ----------------------------------------------------
# TODO: whitelist enforcement test — requires a dnsmasq instance running with
# a whitelist_file containing a single allowed pattern (e.g. "allowed.example")
# so that:
#   - "something.allowed.example" resolves (forwarded upstream)
#   - "denied.example.com" returns NXDOMAIN
# This test is skipped here because the Docker-based DNS test infrastructure
# (docker-compose.test.yml + proxy container) does not yet expose a
# whitelist-file fixture that can be injected at test time without significant
# refactoring of the test compose setup.  The whitelist path in dnsmasq.conf.tmpl
# is already wired; the gap is the per-test fixture injection mechanism.

echo ""
echo "=== DNS Validation Tests: $PASS passed, $FAIL failed ==="
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
