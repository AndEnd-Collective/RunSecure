#!/bin/bash
# ============================================================================
# RunSecure — DNS Whitelist Generator Tests (host-side, no Docker)
# ============================================================================
# Asserts the dnsmasq.conf that generate-egress-conf.sh produces for
# dns.whitelist_file actually restricts resolution to the listed domains.
#
# dnsmasq semantics the assertions rest on:
#   server=<ip>            forward EVERY name to <ip>
#   server=/domain/<ip>    forward domain (and subdomains) to <ip>
#   server=/domain/        never forward domain (answer locally)
#
# The generator used to emit the third form for whitelisted domains while
# keeping the first form for dns.servers. Whitelisted names then failed to
# resolve and every other name was forwarded: the whitelist was inverted and
# restricted nothing.
#
# This test checks the generated directives. It does not start dnsmasq: the
# compose test stack has no way to inject a whitelist fixture yet (see the
# open item in tests/integration/test-dns-validation.sh).
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

# The generator writes fixed paths under infra/. Back up whatever is there and
# put it back on exit so the tree is left as it was found.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-dns-whitelist-test-XXXXXX") || exit 1
GENERATED=(
    "${RUNSECURE_ROOT}/infra/squid/haproxy.cfg"
    "${RUNSECURE_ROOT}/infra/squid/dnsmasq.conf"
    "${RUNSECURE_ROOT}/infra/squid/runtime.conf"
    "${RUNSECURE_ROOT}/infra/runtime-compose.yml"
)
for index in "${!GENERATED[@]}"; do
    if [[ -f "${GENERATED[$index]}" ]]; then
        cp "${GENERATED[$index]}" "${WORK}/backup-${index}"
    fi
done
restore() {
    local index
    for index in "${!GENERATED[@]}"; do
        if [[ -f "${WORK}/backup-${index}" ]]; then
            cp "${WORK}/backup-${index}" "${GENERATED[$index]}"
        else
            rm -f "${GENERATED[$index]}"
        fi
    done
    rm -rf "$WORK"
}
trap restore EXIT

DNSMASQ_CONF="${RUNSECURE_ROOT}/infra/squid/dnsmasq.conf"

# make_project DIR WHITELIST_CONTENT [SERVERS_YAML]
# Writes a project whose runner.yml enables dnsmasq with a local whitelist.
make_project() {
    local dir="$1"
    local whitelist="$2"
    local servers="${3:-    - 10.0.0.53
    - 10.0.0.54}"
    mkdir -p "$dir/.github"
    printf '%s' "$whitelist" > "$dir/allow.txt"
    cat > "$dir/.github/runner.yml" <<EOF
runtime: node:24
dns:
  host: false
  servers:
${servers}
  whitelist_file: ${dir}/allow.txt
EOF
}

# Active (non-comment, non-blank) directives of the generated config.
directives() {
    grep -vE '^[[:space:]]*(#|$)' "$DNSMASQ_CONF"
}

# --- Case 1: whitelist restricts forwarding to the listed domains -----------
PROJ1="${WORK}/proj1"
make_project "$PROJ1" "$(printf 'allowed.example\n# a comment line\n.npmjs.org   # trailing comment\n\n')"

if bash "$GENERATE" "$PROJ1" >"${WORK}/out1" 2>&1 && [[ -f "$DNSMASQ_CONF" ]]; then
    for expected in \
        'server=/allowed.example/10.0.0.53' \
        'server=/allowed.example/10.0.0.54' \
        'server=/npmjs.org/10.0.0.53' \
        'server=/npmjs.org/10.0.0.54'; do
        if directives | grep -qxF "$expected"; then
            pass "whitelisted domain is forwarded: ${expected}"
        else
            fail "whitelisted domain forwarding" "missing '${expected}' in: $(directives | grep '^server' | tr '\n' ' ')"
        fi
    done
    if directives | grep -qE '^server=[^/]'; then
        fail "no catch-all forwarder" "found one, every name would be forwarded: $(directives | grep -E '^server=[^/]' | tr '\n' ' ')"
    else
        pass "no catch-all forwarder when a whitelist is configured"
    fi
    if directives | grep -qE '^server=/[^/]*/$'; then
        fail "no never-forward stanza" "found the inverted form: $(directives | grep -E '^server=/[^/]*/$' | tr '\n' ' ')"
    else
        pass "no 'server=/domain/' never-forward stanza for a whitelisted domain"
    fi
    if directives | grep -qxF 'no-resolv'; then
        pass "no-resolv keeps /etc/resolv.conf from supplying a catch-all upstream"
    else
        fail "no-resolv" "missing, resolv.conf upstreams would forward every name"
    fi
else
    fail "generator" "failed for a valid whitelist: $(tail -3 "${WORK}/out1" | tr '\n' ' ')"
fi

# --- Case 2: without a whitelist, dns.servers stay catch-all forwarders ------
PROJ2="${WORK}/proj2"
mkdir -p "$PROJ2/.github"
cat > "$PROJ2/.github/runner.yml" <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
EOF
if bash "$GENERATE" "$PROJ2" >"${WORK}/out2" 2>&1 && [[ -f "$DNSMASQ_CONF" ]]; then
    if directives | grep -qxF 'server=10.0.0.53'; then
        pass "no whitelist: dns.servers entry is a catch-all forwarder"
    else
        fail "no whitelist" "expected 'server=10.0.0.53', got: $(directives | grep '^server' | tr '\n' ' ')"
    fi
else
    fail "generator" "failed without a whitelist: $(tail -3 "${WORK}/out2" | tr '\n' ' ')"
fi

# --- Case 3: entries that are not domain names are rejected ------------------
# expect_rejected NAME WHITELIST_CONTENT EXPECTED_MESSAGE
expect_rejected() {
    local name="$1"
    local content="$2"
    local message="$3"
    local dir="${WORK}/reject-${PASS}-${FAIL}"
    make_project "$dir" "$content"
    local output
    if output=$(bash "$GENERATE" "$dir" 2>&1); then
        fail "$name" "generator accepted it"
    elif grep -qF "$message" <<<"$output"; then
        pass "$name"
    else
        fail "$name" "rejected, but not with '${message}': $(tail -2 <<<"$output" | tr '\n' ' ')"
    fi
}

expect_rejected "directive smuggled through a whitelist line is rejected" \
    "$(printf 'allowed.example/10.0.0.53\n')" "is not a valid domain name"
expect_rejected "whole top-level domain in the whitelist is rejected" \
    "$(printf 'com\n')" "is not a valid domain name"
expect_rejected "wildcard-everything entry is rejected" \
    "$(printf '#\n.\n')" "is not a valid domain name"
expect_rejected "empty whitelist is rejected instead of denying every name" \
    "$(printf '# nothing allowed yet\n\n')" "contains no domains"

expect_rejected "whitelist entry with an empty label is rejected" \
    "$(printf 'co..uk\n')" "is not a valid domain name"

# --- Case 4: hosts_file without dns.servers stays a valid, closed config -----
PROJ4="${WORK}/proj4"
mkdir -p "$PROJ4/.github"
printf '192.0.2.10 svc.internal.example\n' > "$PROJ4/hosts.txt"
printf 'allowed.example\n' > "$PROJ4/allow.txt"
cat > "$PROJ4/.github/runner.yml" <<EOF
runtime: node:24
dns:
  host: false
  hosts_file: ${PROJ4}/hosts.txt
  whitelist_file: ${PROJ4}/allow.txt
EOF
if bash "$GENERATE" "$PROJ4" >"${WORK}/out4" 2>&1 && [[ -f "$DNSMASQ_CONF" ]]; then
    if directives | grep -qE '^server='; then
        fail "hosts-only config" "emitted a forwarder with no dns.servers: $(directives | grep '^server' | tr '\n' ' ')"
    else
        pass "hosts_file + whitelist without dns.servers: generator succeeds and forwards nothing"
    fi
else
    fail "hosts-only config" "generator failed: $(tail -3 "${WORK}/out4" | tr '\n' ' ')"
fi

# --- Print results ----------------------------------------------------------
echo ""
echo "=== DNS Whitelist Generator Tests ==="
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
