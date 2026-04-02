#!/bin/bash
# ============================================================================
# RunSecure — Runner Validation Suite
# ============================================================================
# Tests that a RunSecure container is properly hardened AND can still run CI.
# This script runs INSIDE a container to validate both security and function.
#
# Usage:
#   docker run --rm [hardening flags] runner-node:24 /path/to/validate-runner.sh
#
# Exit code: 0 if all tests pass, 1 if any fail.
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0
SKIP=0

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
    SKIP=$((SKIP + 1))
}

# ============================================================================
# SECTION 1: Security Hardening Checks
# ============================================================================
echo -e "\n${BOLD}=== Security Hardening Checks ===${NC}\n"

# 1. Non-root user
echo -e "${BOLD}--- User Isolation ---${NC}"
if [[ "$(id -u)" != "0" ]]; then
    pass "Running as non-root (UID: $(id -u))"
else
    fail "Running as root — container should use USER 1001"
fi

# 2. Cannot escalate to root
if command -v su &>/dev/null; then
    fail "su binary exists — should be removed"
else
    pass "su binary removed"
fi

if command -v sudo &>/dev/null; then
    fail "sudo binary exists — should be removed"
else
    pass "sudo binary removed"
fi

# 3. No setuid binaries
echo -e "\n${BOLD}--- Setuid/Setgid Binaries ---${NC}"
SETUID_COUNT=$(find / -perm /6000 -type f 2>/dev/null | wc -l)
if [[ "$SETUID_COUNT" -eq 0 ]]; then
    pass "No setuid/setgid binaries found"
else
    fail "Found $SETUID_COUNT setuid/setgid binaries:"
    find / -perm /6000 -type f 2>/dev/null | head -10
fi

# 4. Package manager cannot function
# In intermediate images, apt binary may exist but --read-only prevents it from
# working. In finalized images (via compose-image.sh), the binary is removed.
echo -e "\n${BOLD}--- Package Manager ---${NC}"
if command -v apt-get &>/dev/null; then
    # Binary exists — check if it can actually do anything
    if apt-get update 2>/dev/null; then
        fail "Package manager is functional — should be neutered by read-only fs or removed"
    else
        pass "apt-get binary exists but cannot function (read-only filesystem)"
    fi
else
    pass "Package manager removed (apt/dpkg not found)"
fi

# 5. No network reconnaissance tools
echo -e "\n${BOLD}--- Network Tools ---${NC}"
for tool in ping traceroute nmap nc ncat netcat ssh scp sftp wget; do
    if command -v "$tool" &>/dev/null; then
        fail "Network tool '$tool' is available — should be removed"
    else
        pass "Network tool '$tool' not found"
    fi
done

# 6. No cron
echo -e "\n${BOLD}--- Persistence Tools ---${NC}"
for tool in crontab at atq atrm; do
    if command -v "$tool" &>/dev/null; then
        fail "Persistence tool '$tool' is available"
    else
        pass "Persistence tool '$tool' not found"
    fi
done

# 7. Root account locked
echo -e "\n${BOLD}--- Root Account ---${NC}"
ROOT_SHELL=$(grep '^root:' /etc/passwd 2>/dev/null | cut -d: -f7)
if [[ "$ROOT_SHELL" == "/usr/sbin/nologin" || "$ROOT_SHELL" == "/bin/false" ]]; then
    pass "Root shell disabled ($ROOT_SHELL)"
else
    fail "Root shell is $ROOT_SHELL — should be /usr/sbin/nologin"
fi

# 8. Read-only filesystem (if mounted with --read-only)
echo -e "\n${BOLD}--- Filesystem ---${NC}"
if touch /test-write-root 2>/dev/null; then
    rm -f /test-write-root
    fail "Root filesystem is writable — use --read-only flag"
else
    pass "Root filesystem is read-only"
fi

if touch /etc/test-write 2>/dev/null; then
    rm -f /etc/test-write
    fail "/etc is writable"
else
    pass "/etc is read-only"
fi

# 9. /tmp exists and is writable but noexec
echo -e "\n${BOLD}--- Tmpfs ---${NC}"
if touch /tmp/test-write 2>/dev/null; then
    pass "/tmp is writable"
    rm -f /tmp/test-write
else
    fail "/tmp is not writable — runner needs writable /tmp"
fi

# Test noexec on /tmp
echo '#!/bin/sh' > /tmp/test-exec.sh 2>/dev/null
echo 'echo "executed"' >> /tmp/test-exec.sh 2>/dev/null
chmod +x /tmp/test-exec.sh 2>/dev/null
if /tmp/test-exec.sh 2>/dev/null; then
    fail "/tmp allows execution — mount with noexec"
else
    pass "/tmp is noexec"
fi
rm -f /tmp/test-exec.sh 2>/dev/null

# 10. Workspace writable
if [[ -d /home/runner/_work ]]; then
    if touch /home/runner/_work/test-write 2>/dev/null; then
        pass "Workspace /home/runner/_work is writable"
        rm -f /home/runner/_work/test-write
    else
        fail "Workspace /home/runner/_work is not writable — runner needs this"
    fi
else
    skip "Workspace check" "/home/runner/_work not mounted"
fi

# ============================================================================
# SECTION 2: Functional Checks (CI Capabilities)
# ============================================================================
echo -e "\n${BOLD}=== Functional Checks ===${NC}\n"

# 11. Git works
echo -e "${BOLD}--- Core Tools ---${NC}"
if git --version &>/dev/null; then
    pass "git is available ($(git --version | head -1))"
else
    fail "git is not available"
fi

# 12. curl works
if curl --version &>/dev/null; then
    pass "curl is available"
else
    fail "curl is not available"
fi

# 13. jq works
if echo '{"test":1}' | jq '.test' &>/dev/null; then
    pass "jq is available and functional"
else
    fail "jq is not available"
fi

# 14. GitHub CLI
if gh --version &>/dev/null; then
    pass "gh CLI is available ($(gh --version | head -1))"
else
    fail "gh CLI is not available"
fi

# 15. GitHub Actions runner
echo -e "\n${BOLD}--- Runner Binary ---${NC}"
RUNNER_DIR="/home/runner/actions-runner"
if [[ -f "${RUNNER_DIR}/run.sh" ]]; then
    pass "Runner binary found at ${RUNNER_DIR}"
else
    fail "Runner binary not found at ${RUNNER_DIR}"
fi

if [[ -x "${RUNNER_DIR}/run.sh" ]]; then
    pass "Runner run.sh is executable"
else
    fail "Runner run.sh is not executable"
fi

# 16. Language runtime (detect which is installed)
echo -e "\n${BOLD}--- Language Runtime ---${NC}"
if command -v node &>/dev/null; then
    pass "Node.js $(node --version) is available"
    if command -v npm &>/dev/null; then
        pass "npm $(npm --version) is available"
    else
        fail "npm is not available"
    fi
elif command -v python3 &>/dev/null; then
    pass "Python $(python3 --version) is available"
    if command -v pip3 &>/dev/null; then
        pass "pip3 is available"
    else
        skip "pip3" "not installed (may not be needed)"
    fi
elif command -v rustc &>/dev/null; then
    pass "Rust $(rustc --version) is available"
    if command -v cargo &>/dev/null; then
        pass "cargo is available"
    else
        fail "cargo is not available"
    fi
else
    skip "Language runtime" "no node/python/rust detected (base image)"
fi

# ============================================================================
# SECTION 3: Resource Limit Checks
# ============================================================================
echo -e "\n${BOLD}=== Resource Limit Checks ===${NC}\n"

# 17. PID limit (try to detect)
echo -e "${BOLD}--- Resource Limits ---${NC}"
PIDS_MAX=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo "unknown")
if [[ "$PIDS_MAX" != "unknown" && "$PIDS_MAX" != "max" ]]; then
    pass "PID limit set: $PIDS_MAX"
else
    skip "PID limit" "cannot read cgroup (may still be enforced)"
fi

# 18. Memory limit
MEM_MAX=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo "unknown")
if [[ "$MEM_MAX" != "unknown" && "$MEM_MAX" != "max" && "$MEM_MAX" != "9223372036854771712" ]]; then
    MEM_MB=$((MEM_MAX / 1048576))
    pass "Memory limit set: ${MEM_MB} MB"
else
    skip "Memory limit" "cannot read cgroup or unlimited"
fi

# 19. CPU limit
CPU_MAX=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo "unknown")
if [[ "$CPU_MAX" != "unknown" && "$CPU_MAX" != "max" ]]; then
    pass "CPU limit set: $CPU_MAX"
else
    skip "CPU limit" "cannot read cgroup"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Results ===${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Skipped:${NC} $SKIP"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}VALIDATION FAILED${NC} — $FAIL checks did not pass."
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL CHECKS PASSED${NC}"
    exit 0
fi
