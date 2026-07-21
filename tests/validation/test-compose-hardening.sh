#!/bin/bash
# ============================================================================
# RunSecure — Compose-File Hardening Assertions
# ============================================================================
# Static assertions about docker-compose.yml + docker-compose.test.yml
# that prevent the hardening posture from accidentally regressing in a
# future commit. These are pure file-content checks — no Docker required.
#
# Covers:
#   M5  : both proxy and runner reference a seccomp profile in security_opt
#   H3  : runner has init: true (PID-1 reaping)
#   H13 : (verified by tests/integration/test-haproxy-cfg-generator.sh)
#
# When more compose-level invariants are added, append checks here.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROD_COMPOSE="${RUNSECURE_ROOT}/infra/docker-compose.yml"
TEST_COMPOSE="${RUNSECURE_ROOT}/tests/integration/docker-compose.test.yml"

PASS=0
FAIL=0
RESULTS=()

pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

# Find the line range of a service block within a compose file.
# Returns: "start_line:end_line" (inclusive). The end is the line before
# the next top-level service or the end of the file.
_service_range() {
    local file="$1"
    local service="$2"
    awk -v s="$service" '
        /^services:/ { in_services=1; next }
        !in_services { next }
        in_services && /^[a-zA-Z]/ { if (started) print start ":" (NR-1); started=0; exit }
        /^  [a-zA-Z][a-zA-Z0-9_-]*:[[:space:]]*$/ {
            cur=$0; sub(/^  /,"",cur); sub(/:.*/,"",cur)
            if (started) { print start ":" (NR-1); started=0; exit }
            if (cur == s) { started=1; start=NR; next }
        }
        END { if (started) print start ":" NR }
    ' "$file"
}

# Assert a regex matches inside the named service block of the named file.
assert_in_service() {
    local file="$1"
    local service="$2"
    local pattern="$3"
    local label="$4"

    local range
    range=$(_service_range "$file" "$service")
    if [[ -z "$range" ]]; then
        fail "$label — service '$service' not found in $(basename "$file")"
        return
    fi
    local start="${range%:*}"
    local end="${range#*:}"

    if sed -n "${start},${end}p" "$file" | grep -qE "$pattern"; then
        pass "$label"
    else
        fail "$label — pattern '$pattern' not found in $service block of $(basename "$file") (lines $start-$end)"
    fi
}

# --- M5: seccomp profile applied to BOTH proxy and runner --------------------
assert_in_service "$PROD_COMPOSE" "proxy"   'seccomp:.*\.json'  "M5: proxy has seccomp profile (prod compose)"
assert_in_service "$PROD_COMPOSE" "runner"  'seccomp:.*\.json'  "M5: runner has seccomp profile (prod compose)"
assert_in_service "$TEST_COMPOSE" "proxy"   'seccomp:.*\.json'  "M5: proxy has seccomp profile (test compose)"
assert_in_service "$TEST_COMPOSE" "runner"  'seccomp:.*\.json'  "M5: runner has seccomp profile (test compose)"

# --- M5: no-new-privileges + cap_drop ALL still in place ---------------------
assert_in_service "$PROD_COMPOSE" "proxy"   'no-new-privileges:true' "no-new-privileges on proxy (prod)"
assert_in_service "$PROD_COMPOSE" "runner"  'no-new-privileges:true' "no-new-privileges on runner (prod)"
assert_in_service "$PROD_COMPOSE" "proxy"   '^[[:space:]]*-[[:space:]]*ALL' "cap_drop: ALL on proxy (prod)"
assert_in_service "$PROD_COMPOSE" "runner"  '^[[:space:]]*-[[:space:]]*ALL' "cap_drop: ALL on runner (prod)"

# --- H3: init: true on runner (PID 1 reaping) -------------------------------
assert_in_service "$PROD_COMPOSE" "runner"  '^[[:space:]]*init:[[:space:]]+true' "H3: init: true on runner (prod)"
assert_in_service "$PROD_COMPOSE" "proxy"   '^[[:space:]]*init:[[:space:]]+true' "H3: init: true on proxy (prod, was already set)"
assert_in_service "$TEST_COMPOSE" "runner"  '^[[:space:]]*init:[[:space:]]+true' "H3: init: true on runner (test)"

# --- M11: test compose uses deploy.resources, not legacy mem_limit/cpus -----
# The legacy keys (top-level mem_limit/cpus/pids_limit) are still honoured
# by docker-compose v2 but exercise a different code path than the
# deploy.resources.limits block in prod. Test must mirror prod's syntax.
TEST_RUNNER_RANGE=$(_service_range "$TEST_COMPOSE" runner)
if [[ -n "$TEST_RUNNER_RANGE" ]]; then
    start="${TEST_RUNNER_RANGE%:*}"; end="${TEST_RUNNER_RANGE#*:}"
    # Strip comments before checking for legacy YAML keys.
    # Legacy keys live at exactly 4-space indent (top level of the
    # service block); the modern equivalents are nested deeper under
    # deploy.resources.limits with 10-space indent — different regex.
    if sed -n "${start},${end}p" "$TEST_COMPOSE" | grep -v '^\s*#' | grep -qE '^    (mem_limit|cpus|pids_limit):'; then
        fail "M11" "test runner still uses legacy mem_limit/cpus/pids_limit instead of deploy.resources"
    else
        pass "M11: test runner uses deploy.resources (no legacy mem_limit/cpus/pids_limit)"
    fi
fi
assert_in_service "$TEST_COMPOSE" "runner"  '^[[:space:]]*deploy:'        "M11: test runner has deploy block"
assert_in_service "$TEST_COMPOSE" "runner"  '^[[:space:]]*resources:'     "M11: test runner has deploy.resources"

# --- M12: test runner has ulimits matching prod ------------------------------
assert_in_service "$TEST_COMPOSE" "runner" '^[[:space:]]*ulimits:'        "M12: test runner has ulimits"
assert_in_service "$TEST_COMPOSE" "runner" '^[[:space:]]*nofile:'         "M12: test runner has nofile ulimit"
assert_in_service "$TEST_COMPOSE" "runner" '^[[:space:]]*nproc:'          "M12: test runner has nproc ulimit"

# --- M13: prod runner has both uppercase AND lowercase proxy env vars -------
assert_in_service "$PROD_COMPOSE" "runner" '^[[:space:]]*-[[:space:]]*HTTP_PROXY=' "M13: prod runner has HTTP_PROXY (uppercase)"
assert_in_service "$PROD_COMPOSE" "runner" '^[[:space:]]*-[[:space:]]*http_proxy=' "M13: prod runner has http_proxy (lowercase)"
assert_in_service "$PROD_COMPOSE" "runner" '^[[:space:]]*-[[:space:]]*HTTPS_PROXY=' "M13: prod runner has HTTPS_PROXY (uppercase)"
assert_in_service "$PROD_COMPOSE" "runner" '^[[:space:]]*-[[:space:]]*https_proxy=' "M13: prod runner has https_proxy (lowercase)"

# --- Task 8: spawn-egress network in compose.scope.yml ----------------------
SCOPE_COMPOSE="${RUNSECURE_ROOT}/infra/orchestrator/compose.scope.yml"

# The spawn-egress network must disable inter-container communication so that
# proxies from different spawns cannot reach each other directly.
if grep -q 'enable_icc.*false' "${SCOPE_COMPOSE}"; then
    pass "T8: spawn-egress disables ICC (enable_icc: false) in compose.scope.yml"
else
    fail "T8: spawn-egress must set enable_icc: \"false\" in compose.scope.yml"
fi

# The network must not be internal: true — it must have outbound host access.
if ! grep -A5 'spawn-egress:' "${SCOPE_COMPOSE}" | grep -q 'internal: true'; then
    pass "T8: spawn-egress is not internal (has outbound access)"
else
    fail "T8: spawn-egress must NOT be internal: true — it provides outbound internet access"
fi

# Both orchestrator and socket-proxy must receive RUNSECURE_EGRESS_NETWORK.
assert_in_service "${SCOPE_COMPOSE}" "orchestrator" \
    'RUNSECURE_EGRESS_NETWORK' \
    "T8: orchestrator service has RUNSECURE_EGRESS_NETWORK env"
assert_in_service "${SCOPE_COMPOSE}" "socket-proxy" \
    'RUNSECURE_EGRESS_NETWORK' \
    "T8: socket-proxy service has RUNSECURE_EGRESS_NETWORK env"

# --- Issue #54 fix 1: orch-egress must have tmpfs for squid runtime dirs ----
# Without these, squid FATALs with "Read-only file system" on pidfile write
# when running under read_only: true (#54 fix 1).
# The orch-egress service block in compose.scope.yml lists tmpfs entries as
#   "- /var/run/squid:..."
# so we check for each dir in the file directly (they only appear in the
# orch-egress tmpfs block; the orchestrator's tmpfs only has /tmp).
EGRESS_RANGE=$(_service_range "${SCOPE_COMPOSE}" "orch-egress")
if [[ -n "$EGRESS_RANGE" ]]; then
    e_start="${EGRESS_RANGE%:*}"; e_end="${EGRESS_RANGE#*:}"
    for squid_dir in /var/run/squid /var/log/squid /var/spool/squid; do
        if sed -n "${e_start},${e_end}p" "${SCOPE_COMPOSE}" | grep -qF "$squid_dir"; then
            pass "Issue54-F1: orch-egress has tmpfs for $squid_dir"
        else
            fail "Issue54-F1: orch-egress must have tmpfs mount for $squid_dir (squid pidfile/log write fails without it)"
        fi
    done
else
    fail "Issue54-F1: orch-egress service not found in ${SCOPE_COMPOSE}"
fi

# --- Issue #54 fix 2: orch-egress must be attached to spawn-egress ----------
# Without this, compose never creates the spawn-egress network and every
# per-spawn proxy attach fails with 404 "network not found" (#54 fix 2).
assert_in_service "${SCOPE_COMPOSE}" "orch-egress" \
    'spawn-egress' \
    "Issue54-F2: orch-egress is attached to spawn-egress (ensures compose creates the network)"

# --- Issue #54 fix 2: orchestrator must NOT be attached to spawn-egress ----
# Verify the orchestrator is confined to internal networks; attaching it to
# spawn-egress or operator-host would break the network-isolation model.
# We check the networks: key of the orchestrator service specifically —
# RUNSECURE_EGRESS_NETWORK env var contains "spawn-egress" in its value
# which is expected and correct; we must not match that.
# The orchestrator service uses "networks: [orch-internal]" (inline list)
# so we look for the inline list form, not a networks block with spawn-egress.
ORCH_RANGE=$(_service_range "${SCOPE_COMPOSE}" "orchestrator")
if [[ -n "$ORCH_RANGE" ]]; then
    o_start="${ORCH_RANGE%:*}"; o_end="${ORCH_RANGE#*:}"
    # Extract only lines under the "networks:" key of the orchestrator block
    # (stop at the next unindented key). Filter out environment variable values
    # that happen to contain "spawn-egress" as a string value.
    if sed -n "${o_start},${o_end}p" "${SCOPE_COMPOSE}" \
           | awk '/^    networks:/{p=1;next} p && /^    [a-zA-Z]/{exit} p' \
           | grep -q 'spawn-egress'; then
        fail "Issue54-F2: orchestrator must NOT be attached to spawn-egress (isolation breach)"
    else
        pass "Issue54-F2: orchestrator is not attached to spawn-egress (isolation preserved)"
    fi

    ORCH_BLOCK=$(sed -n "${o_start},${o_end}p" "${SCOPE_COMPOSE}")
    if grep -qE '^[[:space:]]*-[[:space:]]*operator-host$' <<<"${ORCH_BLOCK}"; then
        fail "Operator endpoints: PAT-holding orchestrator must not attach to operator-host"
    else
        pass "Operator endpoints: PAT-holding orchestrator stays off operator-host"
    fi
    if grep -qE '^[[:space:]]*-[[:space:]]*operator-internal$' <<<"${ORCH_BLOCK}"; then
        pass "Operator endpoints: orchestrator attaches to the relay-only internal bridge"
    else
        fail "Operator endpoints: orchestrator must attach to operator-internal"
    fi
fi

RELAY_RANGE=$(_service_range "${SCOPE_COMPOSE}" "operator-relay")
if [[ -n "$RELAY_RANGE" ]]; then
    relay_start="${RELAY_RANGE%:*}"; relay_end="${RELAY_RANGE#*:}"
    RELAY_BLOCK=$(sed -n "${relay_start},${relay_end}p" "${SCOPE_COMPOSE}")
    LOOPBACK_BIND_COUNT=$(grep -cE 'host_ip:[[:space:]]*127\.0\.0\.1' <<<"${RELAY_BLOCK}" || true)
    if [[ "${LOOPBACK_BIND_COUNT}" -eq 2 ]]; then
        pass "Operator endpoints: health and state ports bind to loopback only"
    else
        fail "Operator endpoints: expected exactly two fixed 127.0.0.1 host bindings"
    fi
    if grep -qE 'host_ip:[[:space:]]*(0\.0\.0\.0|::)' <<<"${RELAY_BLOCK}"; then
        fail "Operator endpoints: wildcard host publication is forbidden"
    else
        pass "Operator endpoints: no wildcard host publication"
    fi
    if grep -qF "\${RUNSECURE_ORCHESTRATOR_HEALTH_PORT:-8080}" <<<"${RELAY_BLOCK}" \
       && grep -qF "\${RUNSECURE_ORCHESTRATOR_STATE_PORT:-8081}" <<<"${RELAY_BLOCK}"; then
        pass "Operator endpoints: published ports default to 8080 and 8081"
    else
        fail "Operator endpoints: expected explicit health/state host-port defaults"
    fi
    if grep -qE '^[[:space:]]*-[[:space:]]*operator-host$' <<<"${RELAY_BLOCK}" \
       && grep -qE '^[[:space:]]*-[[:space:]]*operator-internal$' <<<"${RELAY_BLOCK}"; then
        pass "Operator endpoints: secretless relay bridges only operator networks"
    else
        fail "Operator endpoints: relay must bridge operator-internal and operator-host"
    fi
else
    fail "Operator endpoints: operator-relay service not found"
fi

assert_in_service "${SCOPE_COMPOSE}" "operator-relay" '^[[:space:]]*read_only:[[:space:]]+true' \
    "Operator endpoints: relay root filesystem is read-only"
assert_in_service "${SCOPE_COMPOSE}" "operator-relay" 'no-new-privileges:true' \
    "Operator endpoints: relay has no-new-privileges"
assert_in_service "${SCOPE_COMPOSE}" "operator-relay" '^[[:space:]]*cap_drop:[[:space:]]*\[ALL\]' \
    "Operator endpoints: relay drops all capabilities"

OPERATOR_NETWORK_BLOCK=$(grep -A8 '^  operator-host:' "${SCOPE_COMPOSE}" || true)
if grep -q 'enable_ip_masquerade:[[:space:]]*"false"' <<<"${OPERATOR_NETWORK_BLOCK}"; then
    pass "Operator endpoints: host-publication bridge disables outbound masquerade"
else
    fail "Operator endpoints: operator-host must disable outbound masquerade"
fi
if grep -q 'host_binding_ipv4:[[:space:]]*"127\.0\.0\.1"' <<<"${OPERATOR_NETWORK_BLOCK}"; then
    pass "Operator endpoints: host-publication bridge defaults to loopback"
else
    fail "Operator endpoints: operator-host must default host bindings to loopback"
fi
if grep -q 'internal:[[:space:]]*true' <<<"${OPERATOR_NETWORK_BLOCK}"; then
    fail "Operator endpoints: Docker suppresses host publishing on internal networks"
else
    pass "Operator endpoints: host-publication bridge is not Docker-internal"
fi

OPERATOR_INTERNAL_BLOCK=$(grep -A4 '^  operator-internal:' "${SCOPE_COMPOSE}" || true)
if grep -q 'internal:[[:space:]]*true' <<<"${OPERATOR_INTERNAL_BLOCK}"; then
    pass "Operator endpoints: relay-to-orchestrator bridge is internal"
else
    fail "Operator endpoints: operator-internal must deny host egress"
fi

RELAY_CFG="${RUNSECURE_ROOT}/infra/orchestrator/operator-relay.haproxy.cfg"
if grep -q 'acl health_path path /healthz /readyz' "${RELAY_CFG}" \
   && grep -q 'acl state_path path /metrics /state/snapshot' "${RELAY_CFG}" \
   && [[ "$(grep -c 'http-request deny' "${RELAY_CFG}")" -eq 4 ]]; then
    pass "Operator endpoints: relay allowlists methods and operator paths"
else
    fail "Operator endpoints: relay must deny non-operator HTTP requests"
fi

# --- Print results -----------------------------------------------------------
echo ""
echo "=== Compose Hardening Assertions ==="
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
