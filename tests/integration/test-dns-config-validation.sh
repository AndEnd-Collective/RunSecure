#!/bin/bash
# ============================================================================
# RunSecure — DNS Config Validation Tests (host-side, no Docker)
# ============================================================================
# Tests that validate-schema.sh correctly validates dns: blocks in runner.yml.
#
# These tests run on the host directly (no Docker required).
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALIDATE="${RUNSECURE_ROOT}/infra/scripts/lib/validate-schema.sh"

PASS=0
FAIL=0
RESULTS=()

check() {
    local name="$1"
    local expected_exit="$2"
    local expected_pattern="$3"
    local yml_content="$4"

    local tmpfile
    tmpfile=$(mktemp /tmp/runner-XXXXXX.yml)
    printf '%s\n' "$yml_content" > "$tmpfile"

    local output
    output=$(bash "$VALIDATE" "$tmpfile" 2>&1)
    local actual_exit=$?

    rm -f "$tmpfile"

    local ok=true
    if [[ "$actual_exit" != "$expected_exit" ]]; then
        ok=false
    fi
    if [[ -n "$expected_pattern" ]] && ! echo "$output" | grep -qE "$expected_pattern"; then
        ok=false
    fi

    if [[ "$ok" == true ]]; then
        RESULTS+=("PASS: $name")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAIL: $name (exit=$actual_exit expected=$expected_exit output='$output')")
        FAIL=$((FAIL + 1))
    fi
}

# --- Valid dns configs -------------------------------------------------------
check "dns absent (default host DNS)" 0 "" "$(cat <<'EOF'
runtime: node:24
EOF
)"

check "dns host:true explicit" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: true
EOF
)"

check "dns host:false with server" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
EOF
)"

check "dns host:false with hosts_file only" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  hosts_file: ./infra/dns/hosts.txt
EOF
)"

check "dns host:false with all options" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
  hosts_file: ./infra/dns/hosts.txt
  whitelist_file: https://internal.company.com/allowed.txt
  log_queries: true
EOF
)"

check "dns log_queries false" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
  log_queries: false
EOF
)"

# --- Invalid: host:false no servers no hosts_file ---------------------------
check "dns host:false missing servers and hosts_file" 1 "requires at least dns.servers" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
EOF
)"

# --- Invalid: bad host value -------------------------------------------------
check "dns host:maybe invalid" 1 "dns.host.*true.*false" "$(cat <<'EOF'
runtime: node:24
dns:
  host: maybe
EOF
)"

# --- Invalid: log_queries not boolean ----------------------------------------
check "dns log_queries not boolean" 1 "log_queries.*true.*false" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
  log_queries: yes
EOF
)"

# --- Print results -----------------------------------------------------------
echo ""
echo "=== DNS Config Validation Tests ==="
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
