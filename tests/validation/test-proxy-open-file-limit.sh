#!/bin/bash
# ============================================================================
# RunSecure — the proxy caps its open-file limit before starting its daemons
# ============================================================================
# Squid and HAProxy size internal tables from the open-file limit they
# inherit. On a kind cluster (containerd hands out 1073741816) the per-job
# proxy was OOM-killed at its 256Mi limit before serving a single request,
# so no runner could register and every job stayed queued. Under Docker's
# default (1048576) it idled at about 150 MiB of that 256.
#
# proxy-entrypoint.sh now lowers the limit first. This test runs the real
# entrypoint with stub daemons that report the limit they inherited.
#
# Asserts:
#   - a limit above the ceiling is lowered to the ceiling, and every daemon
#     (squid, haproxy, dnsmasq) inherits the lowered value
#   - a limit already at or below the ceiling is left alone (never raised)
#   - a malformed ceiling stops the proxy instead of starting it uncapped
#   - the cap is applied before any daemon is started
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENTRYPOINT="${RUNSECURE_ROOT}/infra/squid/proxy-entrypoint.sh"

# The entrypoint targets the bash in the proxy image (Debian, 5.x) and uses
# `wait -n`, which needs bash 4.3 or newer. Find one; macOS /bin/bash is 3.2.
RUNNER_BASH=""
for candidate in "$(command -v bash)" /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do
    if [[ -x "$candidate" ]] && "$candidate" -c '(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) ))' 2>/dev/null; then
        RUNNER_BASH="$candidate"
        break
    fi
done
if [[ -z "$RUNNER_BASH" ]]; then
    echo "FAIL: no bash 4.3+ found to run proxy-entrypoint.sh (CI images have one; on macOS: brew install bash)" >&2
    exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-proxy-fd-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# Stub daemons: record the open-file limit they were started with, then exit.
# The entrypoint is fail-closed, so one daemon exiting ends it.
mkdir -p "${tmp}/bin"
for daemon in squid haproxy dnsmasq; do
    cat > "${tmp}/bin/${daemon}" <<STUB
#!/bin/bash
ulimit -n > "${tmp}/seen-${daemon}"
exit 0
STUB
    chmod +x "${tmp}/bin/${daemon}"
done
touch "${tmp}/squid.conf" "${tmp}/haproxy.cfg" "${tmp}/dnsmasq.conf"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# run_entrypoint START_LIMIT CEILING -> exit status; daemons' limits in $tmp/seen-*
run_entrypoint() {
    local start="$1" ceiling="$2"
    rm -f "${tmp}"/seen-*
    (
        ulimit -n "$start"
        env PATH="${tmp}/bin:${PATH}" \
            SQUID_CFG="${tmp}/squid.conf" HAPROXY_CFG="${tmp}/haproxy.cfg" DNSMASQ_CFG="${tmp}/dnsmasq.conf" \
            ENABLE_HAPROXY=true ENABLE_DNSMASQ=true \
            PROXY_MAX_OPEN_FILES="$ceiling" \
            "$RUNNER_BASH" "$ENTRYPOINT"
    ) > "${tmp}/out" 2>&1
}

# Work below this shell's own soft limit so the test never needs to raise it.
available=$(ulimit -n)
if [[ "$available" == "unlimited" ]] || (( available > 4096 )); then
    available=4096
fi
if (( available < 64 )); then
    echo "FAIL: this shell's open-file limit (${available}) is too low to run the test" >&2
    exit 1
fi
high=$available
ceiling=$((available / 2))
low=$((available / 4))

# --- a limit above the ceiling is lowered, for every daemon -----------------
run_entrypoint "$high" "$ceiling" || true
for daemon in squid haproxy dnsmasq; do
    seen=$(cat "${tmp}/seen-${daemon}" 2>/dev/null || echo "not started")
    if [[ "$seen" == "$ceiling" ]]; then
        pass "${daemon} inherits the lowered limit (${high} -> ${ceiling})"
    else
        fail "${daemon} started with open-file limit '${seen}', expected ${ceiling}"
    fi
done
if grep -qF "open-file limit lowered from ${high} to ${ceiling}" "${tmp}/out"; then
    pass "the entrypoint logs that it lowered the limit"
else
    fail "no log line for lowering the limit: $(head -3 "${tmp}/out" | tr '\n' ' ')"
fi

# --- a limit already below the ceiling is never raised ----------------------
run_entrypoint "$low" "$ceiling" || true
seen=$(cat "${tmp}/seen-squid" 2>/dev/null || echo "not started")
if [[ "$seen" == "$low" ]]; then
    pass "a limit below the ceiling is left alone (${low}, ceiling ${ceiling})"
else
    fail "limit ${low} became '${seen}' under ceiling ${ceiling}"
fi

run_entrypoint "$ceiling" "$ceiling" || true
seen=$(cat "${tmp}/seen-squid" 2>/dev/null || echo "not started")
if [[ "$seen" == "$ceiling" ]]; then
    pass "a limit equal to the ceiling is left alone"
else
    fail "limit equal to the ceiling became '${seen}'"
fi

# --- a malformed ceiling stops the proxy ------------------------------------
for bad in 0 -1 lots "65536; id" ""; do
    status=0
    if [[ -z "$bad" ]]; then
        # An empty value means "use the default", which is valid; the default
        # must be the documented 65536 and above this shell's limit, so the
        # limit is left alone.
        run_entrypoint "$low" "" || status=$?
        seen=$(cat "${tmp}/seen-squid" 2>/dev/null || echo "not started")
        if [[ "$seen" == "$low" ]] && grep -q 'PROXY_MAX_OPEN_FILES:-65536' "$ENTRYPOINT"; then
            pass "an empty ceiling falls back to the default of 65536"
        else
            fail "an empty ceiling did not fall back to the default (squid saw '${seen}')"
        fi
        continue
    fi
    run_entrypoint "$high" "$bad" || status=$?
    if [[ "$status" -ne 0 ]] && [[ ! -e "${tmp}/seen-squid" ]] && grep -q 'PROXY_MAX_OPEN_FILES must be a positive integer' "${tmp}/out"; then
        pass "ceiling '${bad}' is rejected before any daemon starts"
    else
        fail "ceiling '${bad}' was not rejected (exit=${status}, squid started: $([[ -e "${tmp}/seen-squid" ]] && echo yes || echo no))"
    fi
done

# --- ordering: the cap comes before the first daemon ------------------------
cap_line=$(grep -n 'ulimit -n "${PROXY_MAX_OPEN_FILES}"' "$ENTRYPOINT" | head -1 | cut -d: -f1)
first_daemon=$(grep -n -E '^\s*(dnsmasq|haproxy|squid) ' "$ENTRYPOINT" | head -1 | cut -d: -f1)
if [[ -n "$cap_line" && -n "$first_daemon" ]] && (( cap_line < first_daemon )); then
    pass "the limit is capped before the first daemon is started"
else
    fail "cap at line '${cap_line}', first daemon at line '${first_daemon}'"
fi

echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
fi
echo "PASSED: $PASS tests"
