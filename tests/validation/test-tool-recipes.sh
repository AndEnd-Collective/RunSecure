#!/bin/bash
# ============================================================================
# RunSecure Validation Test — Tool Recipe Smoke Tests
# ============================================================================
# Verifies that tool recipes (cypress, playwright, semgrep) install correctly
# and leave their binaries available. Each test builds a throwaway image with
# the tool recipe baked in, then checks the binary is present and functional.
#
# Usage:
#   ./tests/validation/test-tool-recipes.sh
#   ./tests/validation/test-tool-recipes.sh --skip-build  # reuse cached images
#
# Prerequisites:
#   - Docker running
#   - runner-base:latest and runner-node:24 images built
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLS_DIR="${RUNSECURE_ROOT}/tools"

SKIP_BUILD=false
for arg in "$@"; do
    [[ "$arg" == "--skip-build" ]] && SKIP_BUILD=true
done

PASS=0
FAIL=0
SKIP_COUNT=0

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

skip() {
    echo -e "  ${YELLOW}SKIP${NC} $1 — $2"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

echo -e "\n${BOLD}=== Tool Recipe Smoke Tests ===${NC}\n"

# Verify base images exist
if ! docker image inspect runner-node:24 &>/dev/null; then
    echo -e "${RED}ERROR: runner-node:24 not found. Build it first.${NC}"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"; docker rmi runsecure-test-cypress runsecure-test-playwright runsecure-test-semgrep 2>/dev/null || true' EXIT

# ============================================================================
# Helper: build a test image with a tool recipe
# ============================================================================
build_tool_image() {
    local tool="$1"
    local base_image="$2"
    local tag="runsecure-test-${tool}"

    if [[ "$SKIP_BUILD" == true ]] && docker image inspect "$tag" &>/dev/null; then
        echo -e "  Using cached image $tag"
        return 0
    fi

    cat > "$TMPDIR/Dockerfile.${tool}" <<EOF
FROM ${base_image}
USER root
COPY tools/${tool}.sh /tmp/install-${tool}.sh
RUN chmod +x /tmp/install-${tool}.sh && /tmp/install-${tool}.sh && rm /tmp/install-${tool}.sh
USER runner
EOF

    docker build \
        -f "$TMPDIR/Dockerfile.${tool}" \
        -t "$tag" \
        "$RUNSECURE_ROOT" 2>&1
}

HARDENING_FLAGS=(
    --rm
    --user 1001:0
    --security-opt=no-new-privileges
    --cap-drop=ALL
)

# ============================================================================
# Test 1: Cypress
# ============================================================================
echo -e "${BOLD}--- 1. Cypress ---${NC}"

if [[ -f "${TOOLS_DIR}/cypress.sh" ]]; then
    echo "  Building cypress test image..."
    if build_tool_image "cypress" "runner-node:24"; then
        pass "Cypress image built successfully"

        # Verify cypress binary exists
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-cypress \
            bash -c "npx cypress --version" 2>&1 | grep -q "Cypress"; then
            pass "cypress --version works"
        else
            fail "cypress --version failed"
        fi

        # Verify the Cypress binary was actually downloaded into the cache
        # (we deliberately skip `cypress verify` itself in this image build
        # because Cypress 14+ on arm64 hangs in the smoke-test under xvfb;
        # see tools/cypress.sh comments). The binary's presence is the
        # meaningful integrity check we can perform headlessly.
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-cypress \
            bash -c "test -x /home/runner/.cache/Cypress/*/Cypress/Cypress" 2>&1; then
            pass "cypress binary present in /home/runner/.cache/Cypress"
        else
            fail "cypress binary not found in /home/runner/.cache/Cypress"
        fi
    else
        fail "Cypress image build failed"
    fi
else
    skip "Cypress" "recipe not found"
fi

# ============================================================================
# Test 2: Playwright
# ============================================================================
echo -e "\n${BOLD}--- 2. Playwright ---${NC}"

if [[ -f "${TOOLS_DIR}/playwright.sh" ]]; then
    echo "  Building playwright test image..."
    if build_tool_image "playwright" "runner-node:24"; then
        pass "Playwright image built successfully"

        # Verify playwright is installed
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-playwright \
            bash -c "npx playwright --version" 2>&1 | grep -q "[0-9]"; then
            pass "playwright --version works"
        else
            fail "playwright --version failed"
        fi

        # Verify chromium browser binary is present
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-playwright \
            bash -c "ls /home/runner/.cache/ms-playwright/chromium-*/chrome-linux*/chrome" 2>&1 | grep -q "chrome"; then
            pass "Chromium binary baked into image"
        else
            fail "Chromium binary not found in image"
        fi

        # Verify file ownership (runner user should own .cache)
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-playwright \
            bash -c "test -O /home/runner/.cache && echo OWNED" 2>&1 | grep -q "OWNED"; then
            pass "~/.cache owned by runner user"
        else
            fail "~/.cache not owned by runner user"
        fi
    else
        fail "Playwright image build failed"
    fi
else
    skip "Playwright" "recipe not found"
fi

# ============================================================================
# Test 3: Semgrep
# ============================================================================
echo -e "\n${BOLD}--- 3. Semgrep ---${NC}"

if [[ -f "${TOOLS_DIR}/semgrep.sh" ]]; then
    echo "  Building semgrep test image..."
    if build_tool_image "semgrep" "runner-node:24"; then
        pass "Semgrep image built successfully (on node base — tests python auto-install)"

        # Verify semgrep binary exists
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-semgrep \
            bash -c "semgrep --version" 2>&1 | grep -q "[0-9]"; then
            pass "semgrep --version works"
        else
            fail "semgrep --version failed"
        fi

        # Verify python3 was auto-installed (semgrep.sh installs it if missing)
        if docker run "${HARDENING_FLAGS[@]}" runsecure-test-semgrep \
            bash -c "python3 --version" 2>&1 | grep -q "Python"; then
            pass "python3 available (auto-installed by semgrep recipe)"
        else
            fail "python3 not available after semgrep install"
        fi
    else
        fail "Semgrep image build failed"
    fi
else
    skip "Semgrep" "recipe not found"
fi

# ============================================================================
# Test 4: Verify tool recipes are valid bash
# ============================================================================
echo -e "\n${BOLD}--- 4. Recipe syntax check ---${NC}"

for recipe in "${TOOLS_DIR}"/*.sh; do
    TOOL_NAME=$(basename "$recipe" .sh)
    if bash -n "$recipe" 2>&1; then
        pass "$TOOL_NAME.sh is valid bash"
    else
        fail "$TOOL_NAME.sh has syntax errors"
    fi
done

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Tool Recipe Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Skipped:${NC} $SKIP_COUNT"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}TOOL RECIPE TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TOOL RECIPE TESTS PASSED${NC}"
    exit 0
fi
