#!/bin/bash
# ============================================================================
# RunSecure — Network Egress Validation
# ============================================================================
# Tests that the Squid proxy correctly blocks unauthorized domains while
# allowing legitimate CI traffic. Run inside a container with proxy configured.
#
# Usage:
#   docker run --rm -e HTTP_PROXY=http://proxy:3128 runner-node:24 \
#     /path/to/validate-network.sh
#
# Exit code: 0 if all tests pass, 1 if any fail.
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    FAIL=$((FAIL + 1))
}

# Test if a URL is reachable (expect HTTP 200 or 301/302)
test_allowed() {
    local url="$1"
    local desc="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
    if [[ "$status" =~ ^(200|301|302|304|403)$ ]]; then
        pass "ALLOWED: $desc ($url) → HTTP $status"
    else
        fail "BLOCKED but should be ALLOWED: $desc ($url) → HTTP $status"
    fi
}

# Test if a URL is blocked (expect connection refused, timeout, or HTTP 403)
test_blocked() {
    local url="$1"
    local desc="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
    if [[ "$status" == "000" || "$status" == "403" || "$status" == "407" ]]; then
        pass "BLOCKED: $desc ($url) → HTTP $status"
    else
        fail "ALLOWED but should be BLOCKED: $desc ($url) → HTTP $status"
    fi
}

# ============================================================================
echo -e "\n${BOLD}=== Network Egress Tests ===${NC}\n"

# Check if proxy is configured
if [[ -z "${HTTP_PROXY:-}" && -z "${HTTPS_PROXY:-}" ]]; then
    echo -e "${RED}WARNING: No proxy configured. Network tests will not validate egress blocking.${NC}"
    echo "Set HTTP_PROXY and HTTPS_PROXY environment variables."
    echo ""
fi

# --- Allowed domains (should succeed) ---
echo -e "${BOLD}--- Domains that SHOULD be allowed ---${NC}"
test_allowed "https://github.com" "GitHub"
test_allowed "https://api.github.com" "GitHub API"
test_allowed "https://registry.npmjs.org" "npm Registry"

# --- Blocked domains (should fail) ---
echo -e "\n${BOLD}--- Domains that SHOULD be blocked ---${NC}"
test_blocked "https://evil.example.com" "Random domain"
test_blocked "https://pastebin.com" "Pastebin (exfiltration target)"
test_blocked "https://webhook.site" "Webhook.site (exfiltration target)"
test_blocked "https://requestbin.com" "RequestBin (exfiltration target)"
test_blocked "https://ngrok.io" "Ngrok (tunneling)"
test_blocked "http://169.254.169.254" "Cloud metadata endpoint"

# ============================================================================
echo -e "\n${BOLD}=== Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}NETWORK VALIDATION FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL NETWORK CHECKS PASSED${NC}"
    exit 0
fi
