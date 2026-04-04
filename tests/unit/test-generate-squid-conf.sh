#!/bin/bash
# ============================================================================
# RunSecure Unit Test — generate-squid-conf.sh
# ============================================================================
# Tests the Squid configuration generator in isolation using temp directories
# with mock runner.yml files. Runs on the host (no Docker required).
#
# Prerequisites: yq installed
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GENERATE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/generate-squid-conf.sh"
BASE_CONF="${RUNSECURE_ROOT}/infra/squid/base.conf"

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

# Create a temp workspace cleaned up on exit
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo -e "\n${BOLD}=== generate-squid-conf.sh Unit Tests ===${NC}\n"

# ============================================================================
# Test 1: No runner.yml — falls back to base config
# ============================================================================
echo -e "${BOLD}--- 1. No runner.yml (fallback) ---${NC}"

PROJECT_1="${TMPDIR}/project-no-yml"
mkdir -p "$PROJECT_1"

# Remove any previous runtime.conf
rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_1" 2>&1)
if [[ $? -eq 0 ]]; then
    pass "Exit code 0 when no runner.yml"
else
    fail "Non-zero exit code when no runner.yml"
fi

if echo "$OUTPUT" | grep -q "No runner.yml"; then
    pass "Reports missing runner.yml"
else
    fail "Does not report missing runner.yml"
fi

if diff -q "$BASE_CONF" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" &>/dev/null; then
    pass "runtime.conf is identical to base.conf"
else
    fail "runtime.conf differs from base.conf"
fi

# ============================================================================
# Test 2: runner.yml with empty egress list
# ============================================================================
echo -e "\n${BOLD}--- 2. Empty egress list ---${NC}"

PROJECT_2="${TMPDIR}/project-empty-egress"
mkdir -p "$PROJECT_2/.github"
cat > "$PROJECT_2/.github/runner.yml" <<'YAML'
runtime: node:24
egress: []
YAML

rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_2" 2>&1)
if [[ $? -eq 0 ]]; then
    pass "Exit code 0 with empty egress"
else
    fail "Non-zero exit code with empty egress"
fi

if echo "$OUTPUT" | grep -q "No project-specific egress"; then
    pass "Reports no project-specific egress"
else
    fail "Does not report empty egress"
fi

if diff -q "$BASE_CONF" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" &>/dev/null; then
    pass "runtime.conf is identical to base.conf (no egress additions)"
else
    fail "runtime.conf differs from base.conf unexpectedly"
fi

# ============================================================================
# Test 3: runner.yml with single egress domain
# ============================================================================
echo -e "\n${BOLD}--- 3. Single egress domain ---${NC}"

PROJECT_3="${TMPDIR}/project-single-domain"
mkdir -p "$PROJECT_3/.github"
cat > "$PROJECT_3/.github/runner.yml" <<'YAML'
runtime: node:24
egress:
  - .example.com
YAML

rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_3" 2>&1)
if [[ $? -eq 0 ]]; then
    pass "Exit code 0 with single domain"
else
    fail "Non-zero exit code with single domain"
fi

RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"
if grep -q "project_egress" "$RUNTIME_CONF"; then
    pass "runtime.conf contains project_egress ACL"
else
    fail "runtime.conf missing project_egress ACL"
fi

if grep -q ".example.com" "$RUNTIME_CONF"; then
    pass "runtime.conf contains .example.com domain"
else
    fail "runtime.conf missing .example.com domain"
fi

if grep -q "http_access allow.*project_egress" "$RUNTIME_CONF"; then
    pass "runtime.conf contains project_egress access rule"
else
    fail "runtime.conf missing project_egress access rule"
fi

# Verify the deny-all rule still exists at the bottom
if grep -q "http_access deny all" "$RUNTIME_CONF"; then
    pass "runtime.conf still has deny-all rule"
else
    fail "runtime.conf lost deny-all rule"
fi

# ============================================================================
# Test 4: runner.yml with multiple egress domains
# ============================================================================
echo -e "\n${BOLD}--- 4. Multiple egress domains ---${NC}"

PROJECT_4="${TMPDIR}/project-multi-domain"
mkdir -p "$PROJECT_4/.github"
cat > "$PROJECT_4/.github/runner.yml" <<'YAML'
runtime: python:3.12
egress:
  - .api.stripe.com
  - .sentry.io
  - .datadog.com
YAML

rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_4" 2>&1)
if [[ $? -eq 0 ]]; then
    pass "Exit code 0 with multiple domains"
else
    fail "Non-zero exit code with multiple domains"
fi

RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"

for domain in ".api.stripe.com" ".sentry.io" ".datadog.com"; do
    if grep -q "$domain" "$RUNTIME_CONF"; then
        pass "runtime.conf contains $domain"
    else
        fail "runtime.conf missing $domain"
    fi
done

# Count how many project_egress ACL lines there are
ACL_COUNT=$(grep -c "acl project_egress dstdomain" "$RUNTIME_CONF" || true)
if [[ "$ACL_COUNT" -eq 3 ]]; then
    pass "Correct number of ACL entries (3)"
else
    fail "Expected 3 ACL entries, found $ACL_COUNT"
fi

# ============================================================================
# Test 5: runner.yml with no egress key at all
# ============================================================================
echo -e "\n${BOLD}--- 5. No egress key in runner.yml ---${NC}"

PROJECT_5="${TMPDIR}/project-no-egress-key"
mkdir -p "$PROJECT_5/.github"
cat > "$PROJECT_5/.github/runner.yml" <<'YAML'
runtime: node:24
tools: []
YAML

rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_5" 2>&1)
if [[ $? -eq 0 ]]; then
    pass "Exit code 0 when egress key is missing"
else
    fail "Non-zero exit code when egress key is missing"
fi

if diff -q "$BASE_CONF" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" &>/dev/null; then
    pass "runtime.conf is base.conf when egress key absent"
else
    fail "runtime.conf differs from base.conf when egress key absent"
fi

# ============================================================================
# Test 6: Generated config preserves base config structure
# ============================================================================
echo -e "\n${BOLD}--- 6. Base config structure preserved ---${NC}"

# Re-use project_3 runtime.conf (single domain)
"$GENERATE_SCRIPT" "$PROJECT_3" &>/dev/null
RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"

# Core sections should remain
if grep -q "http_port 3128" "$RUNTIME_CONF"; then
    pass "http_port preserved"
else
    fail "http_port missing from runtime.conf"
fi

if grep -q "acl github_core" "$RUNTIME_CONF"; then
    pass "github_core ACL preserved"
else
    fail "github_core ACL missing"
fi

if grep -q "acl registries" "$RUNTIME_CONF"; then
    pass "registries ACL preserved"
else
    fail "registries ACL missing"
fi

# Clean up runtime.conf
rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== generate-squid-conf.sh Test Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
