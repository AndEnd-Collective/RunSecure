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

# --- http:// scheme blocked (only https:// allowed for remote) ---------------
check_blocked "http:// scheme remote"         "http://example.com/hosts.txt"

# --- Valid cases: local file paths -------------------------------------------
check_allowed_path "local absolute path"      "/nonexistent/path/hosts.txt"
check_allowed_path "local relative path"      "./infra/dns/hosts.txt"

# --- Valid cases: legitimate HTTPS URLs --------------------------------------
check_allowed_https "valid https external"    "https://example.com/whitelist.txt"
check_allowed_https "valid https with path"   "https://internal.company.com/allowed.txt"

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
