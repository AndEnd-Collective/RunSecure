#!/bin/bash
# ============================================================================
# RunSecure — TCP Egress Validation Tests (host-side, no Docker)
# ============================================================================
# Tests that generate-egress-conf.sh correctly validates and generates
# HAProxy config from tcp_egress entries in runner.yml.
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

# --- Valid tcp_egress entries ------------------------------------------------
check "valid single tcp_egress" 0 "" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:5432
EOF
)"

check "valid multiple distinct ports" 0 "" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:5432
  - redis.example.com:6379
EOF
)"

# --- Invalid: missing port ---------------------------------------------------
check "tcp_egress entry without port" 1 "host:port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech
EOF
)"

# --- Invalid: port 0 ---------------------------------------------------------
check "tcp_egress port 0" 1 "port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:0
EOF
)"

# --- Invalid: port >65535 ----------------------------------------------------
check "tcp_egress port 99999" 1 "port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:99999
EOF
)"

# --- Invalid: port 80 (reserved) --------------------------------------------
check "tcp_egress port 80 reserved" 1 "port.*80|80.*reserved" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:80
EOF
)"

# --- Invalid: port 443 (reserved) -------------------------------------------
check "tcp_egress port 443 reserved" 1 "port.*443|443.*reserved" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:443
EOF
)"

# --- Invalid: duplicate ports -----------------------------------------------
check "tcp_egress duplicate port 5432" 1 "each port must be unique" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - host-a.example.com:5432
  - host-b.example.com:5432
EOF
)"

# --- Valid with both http_egress and tcp_egress ------------------------------
check "valid http_egress + tcp_egress combined" 0 "" "$(cat <<'EOF'
runtime: node:24
http_egress:
  - .npmjs.org
tcp_egress:
  - ep-foo.neon.tech:5432
EOF
)"

# --- Print results -----------------------------------------------------------
echo ""
echo "=== TCP Validation Tests ==="
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
