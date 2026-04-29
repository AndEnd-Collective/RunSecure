#!/bin/bash
# ============================================================================
# RunSecure — Strict Schema Rejection Tests
# ============================================================================
# Tests that validate-schema.sh rejects invalid runner.yml fields and values
# with the exact error messages required by spec §3.3.
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
    shift 3
    local yml_content="$1"

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

# --- Valid config: should pass -----------------------------------------------
check "valid minimal config" 0 "" "runtime: node:24"

check "valid with http_egress" 0 "" "$(cat <<'EOF'
runtime: node:24
http_egress:
  - .npmjs.org
EOF
)"

check "valid with tcp_egress" 0 "" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:5432
EOF
)"

check "valid with dns host:true" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: true
EOF
)"

check "valid with dns host:false and servers" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
EOF
)"

# --- runtime: required -------------------------------------------------------
check "missing runtime" 1 "runtime.*required" "$(cat <<'EOF'
tools:
  - playwright
EOF
)"

# --- runtime: must be a known variant ----------------------------------------
check "invalid runtime variant" 1 "runtime.*invalid" "$(cat <<'EOF'
runtime: java:21
EOF
)"

# --- tcp_egress: must be host:port -------------------------------------------
check "tcp_egress missing port" 1 "tcp_egress.*host:port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech
EOF
)"

check "tcp_egress invalid port zero" 1 "tcp_egress.*port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:0
EOF
)"

check "tcp_egress invalid port too high" 1 "tcp_egress.*port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:99999
EOF
)"

check "tcp_egress duplicate ports" 1 "tcp_egress.*duplicate.*port" "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - host-a.example.com:5432
  - host-b.example.com:5432
EOF
)"

# --- dns: host:false requires servers (unless hosts_file set) ----------------
check "dns host:false no servers no hosts_file" 1 "dns.servers.*required" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
EOF
)"

# --- dns: host:false with only hosts_file is acceptable ----------------------
check "dns host:false with hosts_file only" 0 "" "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  hosts_file: ./infra/dns/hosts.txt
EOF
)"

# --- egress: old key deprecated but still parsed (backward compat) -----------
check "old egress key still accepted" 0 "" "$(cat <<'EOF'
runtime: node:24
egress:
  - .npmjs.org
EOF
)"

# --- http_egress: invalid domain rejected ------------------------------------
check "http_egress with IP rejected" 1 "http_egress.*invalid" "$(cat <<'EOF'
runtime: node:24
http_egress:
  - 192.168.1.1
EOF
)"

# --- unknown top-level key rejected ------------------------------------------
check "unknown top-level key rejected" 1 "unknown.*field|unrecognized.*field" "$(cat <<'EOF'
runtime: node:24
banana: true
EOF
)"

# --- Print results -----------------------------------------------------------
echo ""
echo "=== Schema Rejection Tests ==="
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
