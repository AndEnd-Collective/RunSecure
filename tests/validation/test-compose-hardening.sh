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
