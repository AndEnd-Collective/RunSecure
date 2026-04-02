#!/bin/bash
# ============================================================================
# RunSecure Integration Test — Python CI Workflow
# ============================================================================
# Simulates a real Python CI pipeline running through the egress proxy:
#   1. pip install dependencies from PyPI through proxy
#   2. Run pytest test suite
#   3. Verify package metadata accessible through proxy
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0
WORKDIR="/home/runner/_work/ci-test"

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

echo -e "\n${BOLD}=== Python CI Workflow Simulation ===${NC}"
echo -e "Proxy: ${HTTPS_PROXY:-not set}"
echo -e "Python: $(python3 --version)"
echo -e "pip: $(pip3 --version)\n"

mkdir -p "$WORKDIR"
cp -r /mnt/tests/python-project "$WORKDIR/test-project"
cd "$WORKDIR/test-project"

# ============================================================================
# Step 1: pip install through proxy
# ============================================================================
echo -e "${BOLD}--- Step 1: pip install ---${NC}"

if pip3 install --user --break-system-packages \
    -r requirements.txt 2>&1; then
    pass "pip install fetched packages through proxy"
    if python3 -c "import pytest; print(f'pytest {pytest.__version__}')" 2>&1; then
        pass "pytest importable after install"
    else
        fail "pytest not importable"
    fi
else
    fail "pip install failed through proxy"
fi

# Install an additional package to confirm registry access
if pip3 install --user --break-system-packages requests 2>&1; then
    pass "pip install requests (extra dependency) through proxy"
else
    fail "pip install requests failed through proxy"
fi

# ============================================================================
# Step 2: pytest
# ============================================================================
echo -e "\n${BOLD}--- Step 2: pytest ---${NC}"

export PATH="$HOME/.local/bin:$PATH"

if python3 -m pytest tests/ -v 2>&1; then
    pass "pytest suite passed (10 tests)"
else
    fail "pytest suite failed"
fi

# ============================================================================
# Step 3: Verify PyPI metadata access
# ============================================================================
echo -e "\n${BOLD}--- Step 3: PyPI API access ---${NC}"

# pip search is deprecated, but we can query the JSON API
PYPI_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 \
    "https://pypi.org/pypi/requests/json" 2>/dev/null)
if [[ "$PYPI_CODE" =~ ^(200|301|302)$ ]]; then
    pass "PyPI JSON API accessible through proxy ($PYPI_CODE)"
else
    fail "PyPI JSON API not accessible ($PYPI_CODE)"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Python CI Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}PYTHON CI WORKFLOW FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}PYTHON CI WORKFLOW PASSED${NC}"
    exit 0
fi
