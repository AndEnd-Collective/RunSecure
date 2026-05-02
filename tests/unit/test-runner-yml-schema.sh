#!/bin/bash
# ============================================================================
# RunSecure Unit Test — runner.yml Schema Validation
# ============================================================================
# Tests that the scripts handle malformed or edge-case runner.yml files
# gracefully with clear error messages rather than cryptic yq failures.
#
# Runs on the host (no Docker required). Tests parsing behavior of
# compose-image.sh and generate-egress-conf.sh against various invalid configs.
#
# Prerequisites: yq installed
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/compose-image.sh"
GENERATE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/generate-egress-conf.sh"

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

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo -e "\n${BOLD}=== runner.yml Schema Validation Tests ===${NC}\n"

# ============================================================================
# Test 1: Completely empty runner.yml
# ============================================================================
echo -e "${BOLD}--- 1. Empty runner.yml ---${NC}"

PROJECT_EMPTY="${TMPDIR}/project-empty"
mkdir -p "$PROJECT_EMPTY/.github"
touch "$PROJECT_EMPTY/.github/runner.yml"

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_EMPTY" 2>&1) || EXIT_CODE=$?

# An empty runner.yml has no runtime — compose-image.sh should fail
if [[ $EXIT_CODE -ne 0 ]]; then
    pass "compose-image.sh rejects empty runner.yml (exit $EXIT_CODE)"
else
    fail "compose-image.sh silently accepts empty runner.yml (exit 0)"
fi

# ============================================================================
# Test 2: Missing runtime field
# ============================================================================
echo -e "\n${BOLD}--- 2. Missing runtime field ---${NC}"

PROJECT_NO_RUNTIME="${TMPDIR}/project-no-runtime"
mkdir -p "$PROJECT_NO_RUNTIME/.github"
cat > "$PROJECT_NO_RUNTIME/.github/runner.yml" <<'YAML'
tools:
  - cypress
http_egress:
  - .example.com
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NO_RUNTIME" 2>&1) || EXIT_CODE=$?

# yq '.runtime' on a file without it returns "null"
# compose-image.sh will try to parse "null" into lang:version which should fail
if [[ $EXIT_CODE -ne 0 ]]; then
    pass "compose-image.sh fails on missing runtime field (exit $EXIT_CODE)"
else
    fail "compose-image.sh silently accepts missing runtime (exit 0)"
fi

# ============================================================================
# Test 3: Invalid YAML syntax
# ============================================================================
echo -e "\n${BOLD}--- 3. Invalid YAML syntax ---${NC}"

PROJECT_BAD_YAML="${TMPDIR}/project-bad-yaml"
mkdir -p "$PROJECT_BAD_YAML/.github"
cat > "$PROJECT_BAD_YAML/.github/runner.yml" <<'YAML'
runtime: node:24
  tools: [cypress   # invalid — missing bracket, bad indent
  http_egress:
    - broken
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_BAD_YAML" 2>&1) || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "compose-image.sh fails on invalid YAML (exit $EXIT_CODE)"
else
    fail "compose-image.sh silently accepts invalid YAML (exit 0)"
fi

# generate-egress-conf.sh should fail or produce a valid fallback config
EXIT_CODE=0
OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_BAD_YAML" 2>&1) || EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
    # If it succeeded, it should have fallen back to base config
    if diff -q "${RUNSECURE_ROOT}/infra/squid/base.conf" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" &>/dev/null; then
        pass "generate-egress-conf.sh falls back to base config on invalid YAML"
    else
        fail "generate-egress-conf.sh produced non-base config from invalid YAML"
    fi
else
    pass "generate-egress-conf.sh fails explicitly on invalid YAML (exit $EXIT_CODE)"
fi
rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

# ============================================================================
# Test 4: Runtime with no version separator
# ============================================================================
echo -e "\n${BOLD}--- 4. Runtime without version (no colon) ---${NC}"

PROJECT_NO_VER="${TMPDIR}/project-no-version"
mkdir -p "$PROJECT_NO_VER/.github"
cat > "$PROJECT_NO_VER/.github/runner.yml" <<'YAML'
runtime: node
tools: []
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NO_VER" 2>&1) || EXIT_CODE=$?

# Strict schema validator rejects `runtime: node` (no version) — the regex
# requires `node:<digits>` etc. Failure here is the desired behavior.
if [[ "$EXIT_CODE" -ne 0 ]] && echo "$OUTPUT" | grep -q "runtime 'node' is invalid"; then
    pass "Strict validator rejects runtime without version"
else
    fail "Should reject runtime without version (got: exit=$EXIT_CODE)"
fi

# ============================================================================
# Test 5: Egress with non-list value
# ============================================================================
echo -e "\n${BOLD}--- 5. Egress as string instead of list ---${NC}"

PROJECT_STR_EGRESS="${TMPDIR}/project-str-egress"
mkdir -p "$PROJECT_STR_EGRESS/.github"
cat > "$PROJECT_STR_EGRESS/.github/runner.yml" <<'YAML'
runtime: node:24
http_egress: ".example.com"
YAML

EXIT_CODE=0
OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_STR_EGRESS" 2>&1) || EXIT_CODE=$?

# yq '.egress // [] | .[]' on a scalar string should still produce a domain
# generate-egress-conf.sh uses `|| true` on the yq call, so it may fall back
if [[ $EXIT_CODE -eq 0 ]]; then
    # Check that it either injected the domain or fell back to base
    if grep -q ".example.com" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" 2>/dev/null; then
        pass "generate-egress-conf.sh injected egress string as domain"
    elif diff -q "${RUNSECURE_ROOT}/infra/squid/base.conf" "${RUNSECURE_ROOT}/infra/squid/runtime.conf" &>/dev/null; then
        pass "generate-egress-conf.sh fell back to base config for string egress"
    else
        fail "generate-egress-conf.sh produced unexpected config for string egress"
    fi
else
    fail "generate-egress-conf.sh crashed on egress as string (exit $EXIT_CODE)"
fi
rm -f "${RUNSECURE_ROOT}/infra/squid/runtime.conf"

# ============================================================================
# Test 6: Tools with non-list value
# ============================================================================
echo -e "\n${BOLD}--- 6. Tools as string instead of list ---${NC}"

PROJECT_STR_TOOLS="${TMPDIR}/project-str-tools"
mkdir -p "$PROJECT_STR_TOOLS/.github"
cat > "$PROJECT_STR_TOOLS/.github/runner.yml" <<'YAML'
runtime: node:24
tools: "cypress"
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_STR_TOOLS" 2>&1) || EXIT_CODE=$?

# compose-image.sh should handle or reject tools as string — not crash
if [[ $EXIT_CODE -eq 0 ]]; then
    pass "compose-image.sh handles tools as string (exit 0)"
elif echo "$OUTPUT" | grep -qi "warning\|error"; then
    pass "compose-image.sh rejects tools as string with message"
else
    fail "compose-image.sh crashes on tools as string without error message"
fi

# ============================================================================
# Test 7: Extra/unknown fields are ignored
# ============================================================================
echo -e "\n${BOLD}--- 7. Extra fields ignored ---${NC}"

PROJECT_EXTRA="${TMPDIR}/project-extra"
mkdir -p "$PROJECT_EXTRA/.github"
cat > "$PROJECT_EXTRA/.github/runner.yml" <<'YAML'
runtime: node:24
tools: []
http_egress: []
unknown_field: "should be ignored"
extra:
  nested: true
labels: [self-hosted]
resources:
  memory: 4g
  cpus: 2
  pids: 512
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_EXTRA" 2>&1) || EXIT_CODE=$?

# Strict schema validator rejects unknown top-level keys (PR #20).
# This is intentional: a strict-schema check catches version-skew bugs
# (an old orchestrator with a new config produces a clear error rather
# than silently dropping unknown fields).
if [[ "$EXIT_CODE" -ne 0 ]] && echo "$OUTPUT" | grep -qE 'unknown field "(unknown_field|extra)"'; then
    pass "Strict validator rejects unknown top-level fields"
else
    fail "Should reject unknown fields (got: exit=$EXIT_CODE)"
fi

# ============================================================================
# Test 8: Resource values are strings vs numbers
# ============================================================================
echo -e "\n${BOLD}--- 8. Resource value types ---${NC}"

PROJECT_TYPES="${TMPDIR}/project-types"
mkdir -p "$PROJECT_TYPES/.github"
cat > "$PROJECT_TYPES/.github/runner.yml" <<'YAML'
runtime: node:24
resources:
  memory: 4g
  cpus: 2
  pids: 512
YAML

MEMORY=$(yq '.resources.memory // "8g"' "$PROJECT_TYPES/.github/runner.yml")
CPUS=$(yq '.resources.cpus // "4"' "$PROJECT_TYPES/.github/runner.yml")
PIDS=$(yq '.resources.pids // "2048"' "$PROJECT_TYPES/.github/runner.yml")

if [[ "$MEMORY" == "4g" ]]; then
    pass "Memory parsed as '4g'"
else
    fail "Memory not parsed correctly: $MEMORY"
fi

if [[ "$CPUS" == "2" ]]; then
    pass "CPUs parsed as '2'"
else
    fail "CPUs not parsed correctly: $CPUS"
fi

if [[ "$PIDS" == "512" ]]; then
    pass "PIDs parsed as '512'"
else
    fail "PIDs not parsed correctly: $PIDS"
fi

# ============================================================================
# Test 9: Labels parsing
# ============================================================================
echo -e "\n${BOLD}--- 9. Labels parsing ---${NC}"

PROJECT_LABELS="${TMPDIR}/project-labels"
mkdir -p "$PROJECT_LABELS/.github"
cat > "$PROJECT_LABELS/.github/runner.yml" <<'YAML'
runtime: node:24
labels: [self-hosted, Linux, ARM64, container]
YAML

LABELS=$(yq '.labels // ["self-hosted", "Linux", "ARM64", "container"] | join(",")' "$PROJECT_LABELS/.github/runner.yml")
if [[ "$LABELS" == "self-hosted,Linux,ARM64,container" ]]; then
    pass "Labels parsed and joined correctly"
else
    fail "Labels parsing failed: $LABELS"
fi

# Default labels
PROJECT_NO_LABELS="${TMPDIR}/project-no-labels"
mkdir -p "$PROJECT_NO_LABELS/.github"
cat > "$PROJECT_NO_LABELS/.github/runner.yml" <<'YAML'
runtime: node:24
YAML

LABELS=$(yq '.labels // ["self-hosted", "Linux", "ARM64", "container"] | join(",")' "$PROJECT_NO_LABELS/.github/runner.yml")
if [[ "$LABELS" == "self-hosted,Linux,ARM64,container" ]]; then
    pass "Default labels applied when not specified"
else
    fail "Default labels not applied: $LABELS"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== runner.yml Schema Validation Results ===${NC}"
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
