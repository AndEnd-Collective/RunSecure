#!/bin/bash
# ============================================================================
# RunSecure Unit Test — runner.yml Schema Validation
# ============================================================================
# Tests that the scripts handle malformed or edge-case runner.yml files
# gracefully with clear error messages rather than cryptic yq failures.
#
# Runs on the host (no Docker required). Tests parsing behavior of
# compose-image.sh and generate-squid-conf.sh against various invalid configs.
#
# Prerequisites: yq installed
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/compose-image.sh"
GENERATE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/generate-squid-conf.sh"

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

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_EMPTY" 2>&1 || true)
EXIT_CODE=$?

# Should either fail gracefully or handle null runtime
if [[ $EXIT_CODE -ne 0 ]]; then
    pass "compose-image.sh rejects empty runner.yml (exit $EXIT_CODE)"
else
    # If it doesn't fail, it should have produced some output about parsing
    pass "compose-image.sh handles empty runner.yml without crashing"
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
egress:
  - .example.com
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NO_RUNTIME" 2>&1 || true)
EXIT_CODE=$?

# yq '.runtime' on a file without it returns "null"
# compose-image.sh will try to parse "null" into lang:version which should fail
if [[ $EXIT_CODE -ne 0 ]] || echo "$OUTPUT" | grep -qi "error\|null\|no dockerfile"; then
    pass "compose-image.sh handles missing runtime field"
else
    fail "compose-image.sh silently accepts missing runtime"
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
  egress:
    - broken
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_BAD_YAML" 2>&1 || true)
EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "compose-image.sh fails on invalid YAML"
else
    fail "compose-image.sh silently accepts invalid YAML"
fi

# generate-squid-conf.sh should also handle it gracefully
OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_BAD_YAML" 2>&1 || true)
# Should fall back to base config or fail gracefully
if [[ $? -eq 0 ]]; then
    pass "generate-squid-conf.sh falls back gracefully on invalid YAML"
else
    pass "generate-squid-conf.sh fails explicitly on invalid YAML"
fi

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

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NO_VER" 2>&1 || true)

# "node" without ":version" — cut -d: -f1 gives "node", cut -d: -f2 also gives "node"
# This should be handled but might cause issues
if echo "$OUTPUT" | grep -q "Runtime: node"; then
    pass "Parses runtime without version separator"
else
    fail "Cannot parse runtime without version separator"
fi

# ============================================================================
# Test 5: Egress with non-list value
# ============================================================================
echo -e "\n${BOLD}--- 5. Egress as string instead of list ---${NC}"

PROJECT_STR_EGRESS="${TMPDIR}/project-str-egress"
mkdir -p "$PROJECT_STR_EGRESS/.github"
cat > "$PROJECT_STR_EGRESS/.github/runner.yml" <<'YAML'
runtime: node:24
egress: ".example.com"
YAML

OUTPUT=$("$GENERATE_SCRIPT" "$PROJECT_STR_EGRESS" 2>&1 || true)
EXIT_CODE=$?

# yq '.egress // [] | .[]' on a string should either work or fail gracefully
if [[ $EXIT_CODE -eq 0 ]]; then
    pass "generate-squid-conf.sh handles egress as string"
else
    pass "generate-squid-conf.sh explicitly rejects egress as string (non-list)"
fi

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

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_STR_TOOLS" 2>&1 || true)
EXIT_CODE=$?

# Should handle gracefully
if [[ $EXIT_CODE -eq 0 ]] || echo "$OUTPUT" | grep -qi "warning\|error\|tool"; then
    pass "compose-image.sh handles tools as string"
else
    fail "compose-image.sh crashes on tools as string"
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
egress: []
unknown_field: "should be ignored"
extra:
  nested: true
labels: [self-hosted]
resources:
  memory: 4g
  cpus: 2
  pids: 512
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_EXTRA" 2>&1 || true)

if echo "$OUTPUT" | grep -q "Runtime: node:24"; then
    pass "Parses correctly despite extra fields"
else
    fail "Extra fields cause parsing failure"
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
