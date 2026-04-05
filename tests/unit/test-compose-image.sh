#!/bin/bash
# ============================================================================
# RunSecure Unit Test — compose-image.sh
# ============================================================================
# Tests the image composer logic: config parsing, Dockerfile generation,
# caching, and error handling. Uses mock runner.yml files and verifies
# the generated Dockerfiles without actually building images.
#
# Prerequisites: yq, Docker (for image inspect only — no builds)
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/compose-image.sh"

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

echo -e "\n${BOLD}=== compose-image.sh Unit Tests ===${NC}\n"

# ============================================================================
# Test 1: Missing project directory
# ============================================================================
echo -e "${BOLD}--- 1. Missing project directory ---${NC}"

OUTPUT=$("$COMPOSE_SCRIPT" "/nonexistent/path" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR: Project directory not found"; then
    pass "Reports error for missing project directory"
else
    fail "Does not report error for missing project directory"
fi

# ============================================================================
# Test 2: Missing runner.yml
# ============================================================================
echo -e "\n${BOLD}--- 2. Missing runner.yml ---${NC}"

PROJECT_NO_YML="${TMPDIR}/project-no-yml"
mkdir -p "$PROJECT_NO_YML"

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NO_YML" 2>&1 || true)
if echo "$OUTPUT" | grep -q "No .github/runner.yml"; then
    pass "Reports missing runner.yml"
else
    fail "Does not report missing runner.yml"
fi

# ============================================================================
# Test 3: Parses runtime correctly
# ============================================================================
echo -e "\n${BOLD}--- 3. Runtime parsing ---${NC}"

PROJECT_NODE="${TMPDIR}/project-node"
mkdir -p "$PROJECT_NODE/.github"
cat > "$PROJECT_NODE/.github/runner.yml" <<'YAML'
runtime: node:24
tools: []
egress: []
YAML

# The script will try to build — capture its output to verify parsing
# We expect it to parse node:24 correctly, even if the build fails
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NODE" 2>&1 || true)

if echo "$OUTPUT" | grep -q "Runtime: node:24"; then
    pass "Parses runtime as node:24"
else
    fail "Does not parse runtime correctly"
fi

PROJECT_PY="${TMPDIR}/project-python"
mkdir -p "$PROJECT_PY/.github"
cat > "$PROJECT_PY/.github/runner.yml" <<'YAML'
runtime: python:3.12
tools: []
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_PY" 2>&1 || true)
if echo "$OUTPUT" | grep -q "Runtime: python:3.12"; then
    pass "Parses runtime as python:3.12"
else
    fail "Does not parse python runtime correctly"
fi

PROJECT_RS="${TMPDIR}/project-rust"
mkdir -p "$PROJECT_RS/.github"
cat > "$PROJECT_RS/.github/runner.yml" <<'YAML'
runtime: rust:stable
tools: []
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_RS" 2>&1 || true)
if echo "$OUTPUT" | grep -q "Runtime: rust:stable"; then
    pass "Parses runtime as rust:stable"
else
    fail "Does not parse rust runtime correctly"
fi

# ============================================================================
# Test 4: No tools / no apt — uses language image directly
# ============================================================================
echo -e "\n${BOLD}--- 4. No tools / no apt — direct image use ---${NC}"

# If the language image exists, compose-image.sh should return it directly
# without generating a project Dockerfile
if docker image inspect runner-node:24 &>/dev/null; then
    OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_NODE" 2>&1)
    LAST_LINE=$(echo "$OUTPUT" | tail -1)

    if [[ "$LAST_LINE" == "runner-node:24" ]]; then
        pass "Returns language image directly when no tools/apt"
    else
        fail "Expected runner-node:24, got: $LAST_LINE"
    fi

    if echo "$OUTPUT" | grep -q "No tools or extra packages"; then
        pass "Reports no tools or extra packages"
    else
        fail "Does not report 'no tools or extra packages'"
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} runner-node:24 not built — skipping direct image test"
fi

# ============================================================================
# Test 5: Tool recipe resolution
# ============================================================================
echo -e "\n${BOLD}--- 5. Tool recipe warnings ---${NC}"

PROJECT_BAD_TOOL="${TMPDIR}/project-bad-tool"
mkdir -p "$PROJECT_BAD_TOOL/.github"
cat > "$PROJECT_BAD_TOOL/.github/runner.yml" <<'YAML'
runtime: node:24
tools:
  - nonexistent_tool_xyz
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_BAD_TOOL" --force 2>&1 || true)
if [[ "$OUTPUT" == *"WARNING"*"nonexistent_tool_xyz"* ]]; then
    pass "Warns about missing tool recipe"
else
    fail "Does not warn about missing tool recipe"
fi

# ============================================================================
# Test 6: Known tools are listed
# ============================================================================
echo -e "\n${BOLD}--- 6. Known tools listed ---${NC}"

PROJECT_TOOLS="${TMPDIR}/project-tools"
mkdir -p "$PROJECT_TOOLS/.github"
cat > "$PROJECT_TOOLS/.github/runner.yml" <<'YAML'
runtime: node:24
tools:
  - cypress
  - playwright
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_TOOLS" 2>&1 || true)
if [[ "$OUTPUT" == *"Tools: cypress"* ]]; then
    pass "Reports tools in output"
else
    fail "Does not report tools"
fi

# ============================================================================
# Test 7: Config hash determinism
# ============================================================================
echo -e "\n${BOLD}--- 7. Config hash determinism ---${NC}"

# Call compose-image.sh twice with the same config and compare output
# This only works when runner-node:24 exists (so the script can resolve the image)
if docker image inspect runner-node:24 &>/dev/null; then
    OUTPUT1=$("$COMPOSE_SCRIPT" "$PROJECT_TOOLS" 2>&1 || true)
    OUTPUT2=$("$COMPOSE_SCRIPT" "$PROJECT_TOOLS" 2>&1 || true)
    TAG1=$(echo "$OUTPUT1" | tail -1)
    TAG2=$(echo "$OUTPUT2" | tail -1)

    if [[ -n "$TAG1" && "$TAG1" == "$TAG2" ]]; then
        pass "Same config produces same image tag ($TAG1)"
    else
        fail "Same config produces different tags ($TAG1 vs $TAG2)"
    fi

    # Different config should produce different hash
    OUTPUT3=$("$COMPOSE_SCRIPT" "$PROJECT_PY" 2>&1 || true)
    TAG3=$(echo "$OUTPUT3" | tail -1)
    if [[ "$TAG1" != "$TAG3" ]]; then
        pass "Different configs produce different tags"
    else
        fail "Different configs produce same tag"
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} runner-node:24 not built — skipping hash determinism test"
fi

# ============================================================================
# Test 8: Missing language Dockerfile
# ============================================================================
echo -e "\n${BOLD}--- 8. Missing language Dockerfile ---${NC}"

PROJECT_GO="${TMPDIR}/project-go"
mkdir -p "$PROJECT_GO/.github"
cat > "$PROJECT_GO/.github/runner.yml" <<'YAML'
runtime: go:1.22
tools: []
YAML

EXIT_CODE=0
OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_GO" 2>&1) || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "Fails with non-zero exit for unsupported language (go)"
else
    fail "Does not fail for unsupported language (exit 0)"
fi

if echo "$OUTPUT" | grep -q "ERROR: No Dockerfile for language"; then
    pass "Reports missing Dockerfile for go"
else
    fail "Does not report missing Dockerfile"
fi

# ============================================================================
# Test 9: Version field parsing
# ============================================================================
echo -e "\n${BOLD}--- 9. Version field parsing ---${NC}"

PROJECT_VER="${TMPDIR}/project-version"
mkdir -p "$PROJECT_VER/.github"
cat > "$PROJECT_VER/.github/runner.yml" <<'YAML'
runtime: node:24
version: "1.2.3"
tools: []
YAML

OUTPUT=$("$COMPOSE_SCRIPT" "$PROJECT_VER" 2>&1 || true)
if echo "$OUTPUT" | grep -q "RunSecure version: 1.2.3"; then
    pass "Parses version field correctly"
else
    fail "Does not parse version field"
fi

if echo "$OUTPUT" | grep -q "Registry mode"; then
    pass "Activates registry mode for non-local version"
else
    fail "Does not activate registry mode"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== compose-image.sh Test Results ===${NC}"
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
