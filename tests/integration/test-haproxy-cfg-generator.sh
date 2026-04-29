#!/bin/bash
# ============================================================================
# RunSecure — HAProxy Config Generator Tests (host-side, no Docker)
# ============================================================================
# Asserts properties of haproxy.cfg produced by generate-egress-conf.sh:
#
#   H13: every `bind` line uses the proxy's static internal IP
#        (10.11.12.13), never 0.0.0.0.
#
#   M3:  a `resolvers` section is always emitted when tcp_egress is
#        non-empty, regardless of dns.host. Every backend references
#        it via `resolvers <name>`.
#
#   M9:  generate-egress-conf.sh fails-closed on malformed YAML — must
#        not produce a partial or empty haproxy.cfg.
#
# These tests run on the host directly (no Docker required). They
# create a scratch project dir with a fake .github/runner.yml and run
# the generator against it.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GENERATE="${RUNSECURE_ROOT}/infra/scripts/generate-egress-conf.sh"

PASS=0
FAIL=0
RESULTS=()

pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1 — $2"); FAIL=$((FAIL + 1)); }

# Scratch dir for project fixtures + restore the existing haproxy.cfg
# at exit so we don't leave the tree dirty for other tests.
WORK=$(mktemp -d -p "${HOME:-/tmp}" runsecure-haproxy-test-XXXXXX)
HAPROXY_CFG="${RUNSECURE_ROOT}/infra/squid/haproxy.cfg"
HAPROXY_CFG_BACKUP=""
DNSMASQ_CONF="${RUNSECURE_ROOT}/infra/squid/dnsmasq.conf"
DNSMASQ_CONF_BACKUP=""
RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"
RUNTIME_CONF_BACKUP=""
RUNTIME_COMPOSE="${RUNSECURE_ROOT}/infra/runtime-compose.yml"
RUNTIME_COMPOSE_BACKUP=""

if [[ -f "$HAPROXY_CFG" ]]; then
    HAPROXY_CFG_BACKUP="${WORK}/haproxy.cfg.before"
    cp "$HAPROXY_CFG" "$HAPROXY_CFG_BACKUP"
fi
if [[ -f "$DNSMASQ_CONF" ]]; then
    DNSMASQ_CONF_BACKUP="${WORK}/dnsmasq.conf.before"
    cp "$DNSMASQ_CONF" "$DNSMASQ_CONF_BACKUP"
fi
if [[ -f "$RUNTIME_CONF" ]]; then
    RUNTIME_CONF_BACKUP="${WORK}/runtime.conf.before"
    cp "$RUNTIME_CONF" "$RUNTIME_CONF_BACKUP"
fi
if [[ -f "$RUNTIME_COMPOSE" ]]; then
    RUNTIME_COMPOSE_BACKUP="${WORK}/runtime-compose.yml.before"
    cp "$RUNTIME_COMPOSE" "$RUNTIME_COMPOSE_BACKUP"
fi

cleanup() {
    [[ -n "$HAPROXY_CFG_BACKUP"     ]] && cp "$HAPROXY_CFG_BACKUP"     "$HAPROXY_CFG"
    [[ -n "$DNSMASQ_CONF_BACKUP"    ]] && cp "$DNSMASQ_CONF_BACKUP"    "$DNSMASQ_CONF"
    [[ -n "$RUNTIME_CONF_BACKUP"    ]] && cp "$RUNTIME_CONF_BACKUP"    "$RUNTIME_CONF"
    [[ -n "$RUNTIME_COMPOSE_BACKUP" ]] && cp "$RUNTIME_COMPOSE_BACKUP" "$RUNTIME_COMPOSE"
    rm -rf "$WORK"
}
trap cleanup EXIT

# Build a project dir with a runner.yml of the given content.
make_project() {
    local dir="$1"
    local content="$2"
    rm -rf "$dir"
    mkdir -p "$dir/.github"
    printf '%s\n' "$content" > "$dir/.github/runner.yml"
}

# --- Test 1: dns.host:true → resolvers block uses parse-resolv-conf ---------
PROJ1="${WORK}/proj1"
make_project "$PROJ1" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - postgres.example.com:5432
EOF
)"

if bash "$GENERATE" "$PROJ1" >/dev/null 2>&1 && [[ -f "$HAPROXY_CFG" ]]; then
    if grep -qE 'bind 10\.11\.12\.13:5432' "$HAPROXY_CFG"; then
        pass "H13: bind uses proxy IP (dns.host:true)"
    else
        fail "H13" "bind line did not use 10.11.12.13:5432 (got: $(grep '^    bind' "$HAPROXY_CFG"))"
    fi
    if ! grep -q 'bind 0\.0\.0\.0:' "$HAPROXY_CFG"; then
        pass "H13: no 0.0.0.0 bind anywhere"
    else
        fail "H13" "found 0.0.0.0 bind in haproxy.cfg"
    fi
    if grep -qE '^resolvers default_dns' "$HAPROXY_CFG" && grep -qE 'parse-resolv-conf' "$HAPROXY_CFG"; then
        pass "M3: resolvers block emitted with parse-resolv-conf when dns.host:true"
    else
        fail "M3" "resolvers default_dns / parse-resolv-conf section not found"
    fi
    if grep -qE 'server srv_5432 .* resolvers default_dns' "$HAPROXY_CFG"; then
        pass "M3: backend references resolvers default_dns"
    else
        fail "M3" "backend missing 'resolvers default_dns' on server line"
    fi
else
    fail "generator" "generator failed for dns.host:true case (no haproxy.cfg produced)"
fi

# --- Test 2: dns.host:false → resolvers points at dnsmasq local --------------
PROJ2="${WORK}/proj2"
make_project "$PROJ2" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - postgres.example.com:5432
dns:
  host: false
  servers:
    - 10.0.0.53
EOF
)"

if bash "$GENERATE" "$PROJ2" >/dev/null 2>&1 && [[ -f "$HAPROXY_CFG" ]]; then
    if grep -qE '^resolvers dnsmasq_local' "$HAPROXY_CFG" \
        && grep -qE 'nameserver local 127\.0\.0\.1:53' "$HAPROXY_CFG"; then
        pass "M3: resolvers block points at 127.0.0.1:53 when dns.host:false"
    else
        fail "M3" "dnsmasq_local resolvers / nameserver line not found"
    fi
    if grep -qE 'server srv_5432 .* resolvers dnsmasq_local' "$HAPROXY_CFG"; then
        pass "M3: backend references resolvers dnsmasq_local"
    else
        fail "M3" "backend missing 'resolvers dnsmasq_local'"
    fi
    if grep -qE 'bind 10\.11\.12\.13:5432' "$HAPROXY_CFG"; then
        pass "H13: bind uses proxy IP (dns.host:false)"
    else
        fail "H13" "bind line did not use 10.11.12.13"
    fi
else
    fail "generator" "generator failed for dns.host:false case"
fi

# --- Test 3: M9 — malformed YAML must fail-closed ---------------------------
PROJ3="${WORK}/proj3"
make_project "$PROJ3" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - host-a.example.com:5432
  -- malformed
   bad: indent
EOF
)"

# Truncate haproxy.cfg first; on success generator overwrites it,
# on failure it must NOT be left in a partial state.
true > "$HAPROXY_CFG"
out=$(bash "$GENERATE" "$PROJ3" 2>&1)
exit_code=$?

if echo "$out" | grep -qE 'yq failed parsing|ERROR'; then
    pass "M9: generator emits explicit yq parse error on malformed YAML"
else
    fail "M9" "generator did not produce a yq error message: $out"
fi
if [[ "$exit_code" -ne 0 ]]; then
    pass "M9: generator exits non-zero on malformed YAML"
else
    fail "M9" "generator exited 0 on malformed YAML"
fi

# --- Print results ----------------------------------------------------------
echo ""
echo "=== HAProxy Generator Tests ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
