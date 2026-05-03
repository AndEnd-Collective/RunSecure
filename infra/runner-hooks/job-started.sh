#!/bin/bash
# ============================================================================
# RunSecure — Job-Started Hook
# ============================================================================
# Fires at the start of every job picked up by a RunSecure runner. The
# actions-runner pipes our stdout into the workflow log as a real
# "Job started hook" step, so this output appears in the GitHub Actions
# UI right alongside the job's own steps.
#
# Use this to publish hardening posture, runtime info, and debugging
# pointers — making RunSecure jobs self-explanatory in the UI without
# requiring the user to clone this repo.
#
# IMPORTANT: this script MUST exit 0. A non-zero exit from a job-started
# hook is treated as a job failure by the actions-runner. Wrap any
# command that might fail with `|| true`. The trap below is a safety net.
# ============================================================================

# Catch any unexpected error and exit 0 anyway — a diagnostic hook should
# never be the reason a job fails.
trap 'exit 0' ERR
set -uo pipefail

_safe() { "$@" 2>/dev/null || true; }

echo "::group::RunSecure container — runtime posture"
echo "Image:           $(_safe cat /etc/os-release | _safe grep PRETTY_NAME | _safe cut -d= -f2 | _safe tr -d '\"')"
echo "Kernel:          $(_safe uname -srm)"
echo "Architecture:    $(_safe uname -m)"
echo "User:            $(_safe id -u):$(_safe id -g) ($(_safe whoami))"
echo "ImageOS:         ${ImageOS:-(unset)}"
echo "ImageVersion:    ${ImageVersion:-(unset)}"
echo "Hostname:        $(_safe hostname)"
echo "::endgroup::"

echo "::group::RunSecure container — hardening properties"
# Capabilities (effective set is the only one that actually grants powers)
CAP_EFF=$(_safe grep '^CapEff:' /proc/self/status | awk '{print $2}')
echo "Effective caps:  ${CAP_EFF:-(unreadable)}  (0000000000000000 = empty = cap_drop ALL)"
# NoNewPrivs flag set by --security-opt no-new-privileges:true
NNP=$(_safe grep '^NoNewPrivs:' /proc/self/status | awk '{print $2}')
echo "NoNewPrivs:      ${NNP:-(unknown)}            (1 = setuid-escalation blocked)"
# Seccomp filter mode (2 = filter active)
SECCOMP=$(_safe grep '^Seccomp:' /proc/self/status | awk '{print $2}')
echo "Seccomp mode:    ${SECCOMP:-(unknown)}            (0=disabled  1=strict  2=filter active)"
# /tmp mount flags
TMP_OPTS=$(_safe awk '$2 == "/tmp" {print $4}' /proc/mounts)
echo "/tmp options:    ${TMP_OPTS:-(unknown)}"
# /etc immutability check
ETC_MODE=$(_safe stat -c '%a' /etc)
PASSWD_MODE=$(_safe stat -c '%a' /etc/passwd)
echo "/etc mode:       ${ETC_MODE:-(unknown)} (555 = locked)   /etc/passwd: ${PASSWD_MODE:-(unknown)} (444 = locked)"
echo "::endgroup::"

echo "::group::RunSecure container — network posture"
echo "HTTP_PROXY:      ${HTTP_PROXY:-(unset)}"
echo "HTTPS_PROXY:     ${HTTPS_PROXY:-(unset)}"
echo "NO_PROXY:        ${NO_PROXY:-(unset)}"
echo "DNS resolvers:"
_safe awk '$1 == "nameserver" {print "  " $2}' /etc/resolv.conf
echo "Default route:"
_safe ip route show default 2>/dev/null | head -3 | sed 's/^/  /'
echo "(internal-only network: no default route is expected — egress is via the proxy)"
echo "::endgroup::"

echo "::group::RunSecure container — available toolchains"
for tool in node npm python3 pip3 go cargo gh git curl jq yq; do
    if command -v "$tool" >/dev/null 2>&1; then
        version=$("$tool" --version 2>&1 | head -1)
        printf '  %-8s  %s\n' "$tool" "$version"
    fi
done
echo "::endgroup::"

echo "::group::RunSecure debugging pointers"
echo "If your job behaved unexpectedly, here's where to look:"
echo ""
echo "  Egress denied?"
echo "    The proxy log on the orchestrator host is at _diag-proxy/access.log"
echo "    Add domains to your project's runner.yml under http_egress:"
echo "    Or for raw TCP: tcp_egress: [\"host:port\"]"
echo ""
echo "  Per-job worker log (after the job ends):"
echo "    _diag/Worker_<timestamp>.log on the orchestrator host"
echo "    (set RUNSECURE_DIAG_RETENTION=0 on shared hosts to disable)"
echo ""
echo "  DNS resolution issues?"
echo "    Set 'dns: { host: false, log_queries: true }' in runner.yml"
echo "    Then check _diag-proxy/dnsmasq.log on the orchestrator"
echo ""
echo "  Need to escape a hardening rule (curl/jq/etc removed)?"
echo "    The 'hardening:' block in runner.yml is opt-in — see README"
echo ""
echo "  Full RunSecure docs: https://github.com/AndEnd-Collective/RunSecure"
echo "  Threat model:        https://github.com/AndEnd-Collective/RunSecure/blob/main/SECURITY.md"
echo "::endgroup::"

exit 0
