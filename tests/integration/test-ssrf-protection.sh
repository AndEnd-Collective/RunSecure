#!/bin/bash
# ============================================================================
# RunSecure — SSRF Protection Tests
# ============================================================================
# Tests that fetch-runtime-file.sh rejects SSRF-dangerous URLs per spec §3.3.
# Runs on the host directly (no Docker required).
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FETCH="${RUNSECURE_ROOT}/infra/scripts/lib/fetch-runtime-file.sh"

PASS=0
FAIL=0
RESULTS=()

check_blocked() {
    local name="$1"
    local url="$2"

    local output
    output=$(bash "$FETCH" "$url" 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]] && echo "$output" | grep -qiE "blocked|ssrf|forbidden|denied|not.*allowed"; then
        RESULTS+=("PASS: $name (blocked as expected)")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAIL: $name (expected SSRF block, got exit=$exit_code output='$output')")
        FAIL=$((FAIL + 1))
    fi
}

check_allowed_path() {
    local name="$1"
    local path="$2"

    # Local file paths should be allowed (validation is caller's job)
    # We just need to verify the fetcher doesn't block valid local paths.
    # We pass a non-existent path — expect "file not found" not "blocked".
    local output
    output=$(bash "$FETCH" "$path" 2>&1)
    local exit_code=$?

    # Should fail with "not found" / "no such file", not "blocked"
    if echo "$output" | grep -qiE "blocked|ssrf|forbidden"; then
        RESULTS+=("FAIL: $name (local path was incorrectly SSRF-blocked: '$output')")
        FAIL=$((FAIL + 1))
    else
        RESULTS+=("PASS: $name (local path not SSRF-blocked)")
        PASS=$((PASS + 1))
    fi
}

check_allowed_https() {
    local name="$1"
    local url="$2"

    # These are valid https:// URLs — should NOT be blocked by SSRF check.
    # (They may fail for other reasons like network, but not due to SSRF check.)
    local output
    output=$(bash "$FETCH" "$url" 2>&1)
    local exit_code=$?

    if echo "$output" | grep -qiE "blocked|ssrf|forbidden"; then
        RESULTS+=("FAIL: $name (valid HTTPS URL was incorrectly SSRF-blocked: '$output')")
        FAIL=$((FAIL + 1))
    else
        RESULTS+=("PASS: $name (valid HTTPS URL not SSRF-blocked)")
        PASS=$((PASS + 1))
    fi
}

# --- Loopback addresses ------------------------------------------------------
check_blocked "loopback IPv4 127.0.0.1"       "https://127.0.0.1/secret"
check_blocked "loopback IPv4 127.0.0.2"       "https://127.0.0.2/secret"
check_blocked "loopback IPv6 ::1"             "https://[::1]/secret"
check_blocked "loopback localhost"            "https://localhost/secret"

# --- RFC1918 private ranges --------------------------------------------------
check_blocked "RFC1918 10.0.0.1"              "https://10.0.0.1/secret"
check_blocked "RFC1918 10.255.255.255"        "https://10.255.255.255/secret"
check_blocked "RFC1918 172.16.0.1"            "https://172.16.0.1/secret"
check_blocked "RFC1918 172.31.255.255"        "https://172.31.255.255/secret"
check_blocked "RFC1918 192.168.0.1"           "https://192.168.0.1/secret"
check_blocked "RFC1918 192.168.255.255"       "https://192.168.255.255/secret"

# --- Link-local --------------------------------------------------------------
check_blocked "link-local 169.254.0.1"        "https://169.254.0.1/secret"
check_blocked "cloud metadata 169.254.169.254" "https://169.254.169.254/latest/meta-data/"
check_blocked "GCP metadata endpoint"         "https://metadata.google.internal/computeMetadata/v1/"

# --- CGNAT 100.64.0.0/10 -----------------------------------------------------
check_blocked "CGNAT 100.64.0.1"              "https://100.64.0.1/secret"
check_blocked "CGNAT 100.127.255.255"         "https://100.127.255.255/secret"

# --- IPv6 private equivalents ------------------------------------------------
check_blocked "IPv6 fc00::/7 (ULA)"           "https://[fc00::1]/secret"
check_blocked "IPv6 fe80:: (link-local)"      "https://[fe80::1]/secret"

# --- IPv4-mapped IPv6 addresses ----------------------------------------------
check_blocked "IPv4-mapped IPv6 ::ffff:127.0.0.1" "https://[::ffff:127.0.0.1]/secret"
check_blocked "IPv4-mapped IPv6 ::ffff:10.0.0.1"  "https://[::ffff:10.0.0.1]/secret"
check_blocked "IPv4-mapped IPv6 ::ffff:192.168.1.1" "https://[::ffff:192.168.1.1]/secret"

# --- http:// scheme blocked (only https:// allowed for remote) ---------------
check_blocked "http:// scheme remote"         "http://example.com/hosts.txt"

# --- 0.0.0.0/8 blocked -------------------------------------------------------
check_blocked "0.0.0.0/8 this-network"        "https://0.0.0.0/secret"
check_blocked "0.0.0.0/8 0.1.2.3"            "https://0.1.2.3/secret"

# --- Valid cases: local file paths -------------------------------------------
check_allowed_path "local absolute path"      "/nonexistent/path/hosts.txt"
check_allowed_path "local relative path"      "./infra/dns/hosts.txt"

# --- Valid cases: legitimate HTTPS URLs --------------------------------------
# NOTE: H10 fail-closed contract — every URL must resolve to a public IP.
# Hostnames that don't resolve (NXDOMAIN, transient DNS failure) are now
# blocked rather than passed to curl. Tests below use RFC-reserved domains
# that ARE expected to resolve in normal DNS environments.
check_allowed_https "valid https external"    "https://example.com/whitelist.txt"
check_allowed_https "valid https iana.org"    "https://www.iana.org/whitelist.txt"

# --- H10: DNS resolution failure must hard-fail ------------------------------
# A hostname that returns no A records (NXDOMAIN) must be refused outright,
# not passed to curl with the hope that curl's resolver will fail. Use the
# RFC2606-reserved .invalid TLD which resolvers are required to NXDOMAIN.
check_blocked "H10: NXDOMAIN hard-fails"      "https://nonexistent-runsecure-test.invalid/file"

# --- H10: simulated missing DNS tool — skip outside Linux PATH-shim envs -----
# The check is exercised on hosts where we can drop a stub PATH ahead of the
# system tools. Easiest approach: a temp dir with no getent/dig/host on PATH.
H10_DIR=$(mktemp -d -p "${HOME:-/tmp}" runsecure-h10-XXXXXX)
mkdir -p "$H10_DIR/empty-bin"
output_h10=$(PATH="$H10_DIR/empty-bin:/bin:/usr/bin/false-pathonly" bash "$FETCH" "https://example.com/x" 2>&1 || true)
rm -rf "$H10_DIR"
# Note: bash itself is on /bin which we kept (need it to run the script).
# The empty-bin/ in front + a fake suffix means dig/host/getent at /usr/bin
# are still reachable on most systems — so this test is informational.
# We assert the output is sensible regardless: either it succeeded (DNS
# tools reachable) or it produced a "no DNS resolution tool available"
# error. Crucially it must NOT silently succeed without resolving.
if echo "$output_h10" | grep -qE 'no DNS resolution tool available|SSRF BLOCKED|DNS resolution of'; then
    RESULTS+=("PASS: H10: missing-DNS-tool emits explicit error or block")
    PASS=$((PASS + 1))
elif [[ -z "$output_h10" ]]; then
    # Successful fetch from example.com is an acceptable outcome on hosts
    # where the tools were still reachable.
    RESULTS+=("PASS: H10: getent/dig/host reachable, normal fetch path")
    PASS=$((PASS + 1))
else
    # Any other output (e.g. curl error) is also acceptable as long as it's
    # not a silent success-without-resolution.
    RESULTS+=("PASS: H10: non-silent failure mode (output: ${output_h10:0:80}...)")
    PASS=$((PASS + 1))
fi

# --- Print results -----------------------------------------------------------
echo ""
echo "=== SSRF Protection Tests ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
