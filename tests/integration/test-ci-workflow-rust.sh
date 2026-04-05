#!/bin/bash
# ============================================================================
# RunSecure Integration Test — Rust CI Workflow
# ============================================================================
# Simulates a real Rust CI pipeline running through the egress proxy:
#   1. cargo build (fetches crates through proxy from crates.io)
#   2. cargo test
#   3. Verify crates.io API accessible through proxy
#
# This proves that a full Rust CI lifecycle works with all security
# hardening and network restrictions active.
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

echo -e "\n${BOLD}=== Rust CI Workflow Simulation ===${NC}"
echo -e "Proxy: ${HTTPS_PROXY:-not set}"
echo -e "Rust: $(rustc --version)"
echo -e "Cargo: $(cargo --version)\n"

mkdir -p "$WORKDIR"
cp -r /mnt/tests/rust-project "$WORKDIR/test-project"
cd "$WORKDIR/test-project"

# ============================================================================
# Step 1: cargo build
# ============================================================================
echo -e "${BOLD}--- Step 1: cargo build ---${NC}"

if cargo build 2>&1; then
    pass "cargo build succeeded"
    if [[ -d "target/debug" ]]; then
        pass "Build artifacts created in target/debug/"
    else
        fail "No build artifacts in target/debug/"
    fi
else
    fail "cargo build failed"
fi

# ============================================================================
# Step 2: cargo test
# ============================================================================
echo -e "\n${BOLD}--- Step 2: cargo test ---${NC}"

if cargo test 2>&1; then
    pass "cargo test passed"
else
    fail "cargo test failed"
fi

# ============================================================================
# Step 3: cargo build with a dependency (fetch from crates.io through proxy)
# ============================================================================
echo -e "\n${BOLD}--- Step 3: Fetch dependency from crates.io ---${NC}"

# Add a small, well-known dependency to force registry access
cat > Cargo.toml <<'TOML'
[package]
name = "runsecure-test-rust"
version = "0.1.0"
edition = "2021"

[dependencies]
once_cell = "1"
TOML

if cargo build 2>&1; then
    pass "cargo build with crates.io dependency through proxy"
else
    fail "cargo build with dependency failed (crates.io may be blocked)"
fi

# ============================================================================
# Step 4: Verify crates.io API access through proxy
# ============================================================================
echo -e "\n${BOLD}--- Step 4: crates.io API access ---${NC}"

CRATES_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 \
    "https://crates.io/api/v1/crates/serde" 2>/dev/null)
if [[ "$CRATES_CODE" =~ ^(200|301|302)$ ]]; then
    pass "crates.io API accessible through proxy ($CRATES_CODE)"
else
    fail "crates.io API not accessible ($CRATES_CODE)"
fi

# ============================================================================
# Step 5: Verify build ran as non-root
# ============================================================================
echo -e "\n${BOLD}--- Step 5: Build user verification ---${NC}"

BUILD_UID=$(id -u)
if [[ "$BUILD_UID" == "1001" ]]; then
    pass "Build ran as UID 1001 (non-root)"
else
    fail "Build ran as UID $BUILD_UID (expected 1001)"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Rust CI Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}RUST CI WORKFLOW FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}RUST CI WORKFLOW PASSED${NC}"
    exit 0
fi
