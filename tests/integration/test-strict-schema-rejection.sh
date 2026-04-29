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

# check NAME EXPECTED_EXIT EXPECTED_EXACT_STRING YML_CONTENT
# expected_exact_string: empty string = don't check output content
check() {
    local name="$1"
    local expected_exit="$2"
    local expected_string="$3"
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
    # Exact-string match (substring, not regex, when string is non-empty)
    if [[ -n "$expected_string" ]] && ! echo "$output" | grep -qF "$expected_string"; then
        ok=false
    fi

    if [[ "$ok" == true ]]; then
        RESULTS+=("PASS: $name")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAIL: $name (exit=$actual_exit expected=$expected_exit output='$output' expected_string='$expected_string')")
        FAIL=$((FAIL + 1))
    fi
}

# check_warn NAME EXPECTED_WARN_STRING YML_CONTENT
# Asserts: exits 0 AND the exact warning string appears in stderr/stdout
check_warn() {
    local name="$1"
    local expected_string="$2"
    local yml_content="$3"

    local tmpfile
    tmpfile=$(mktemp /tmp/runner-XXXXXX.yml)
    printf '%s\n' "$yml_content" > "$tmpfile"

    local output
    output=$(bash "$VALIDATE" "$tmpfile" 2>&1)
    local actual_exit=$?

    rm -f "$tmpfile"

    local ok=true
    if [[ "$actual_exit" != "0" ]]; then
        ok=false
    fi
    if ! echo "$output" | grep -qF "$expected_string"; then
        ok=false
    fi

    if [[ "$ok" == true ]]; then
        RESULTS+=("PASS: $name")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAIL: $name (exit=$actual_exit expected=0 output='$output' expected_string='$expected_string')")
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
check "missing runtime" 1 "runtime is required" "$(cat <<'EOF'
tools:
  - playwright
EOF
)"

# --- runtime: must be a known variant ----------------------------------------
check "invalid runtime variant" 1 "runtime 'java:21' is invalid" "$(cat <<'EOF'
runtime: java:21
EOF
)"

# --- tcp_egress: must be host:port -------------------------------------------
check "tcp_egress missing port" 1 \
    'tcp_egress: invalid entry "ep-foo.neon.tech" — expected host:port' \
    "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech
EOF
)"

check "tcp_egress invalid port zero" 1 \
    'tcp_egress: port 0 in "ep-foo.neon.tech:0" out of range (1-65535)' \
    "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:0
EOF
)"

check "tcp_egress invalid port too high" 1 \
    'tcp_egress: port 99999 in "ep-foo.neon.tech:99999" out of range (1-65535)' \
    "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - ep-foo.neon.tech:99999
EOF
)"

check "tcp_egress duplicate ports" 1 \
    'tcp_egress: port 5432 declared by both "host-a.example.com:5432" and "host-b.example.com:5432" — each port must be unique' \
    "$(cat <<'EOF'
runtime: node:24
tcp_egress:
  - host-a.example.com:5432
  - host-b.example.com:5432
EOF
)"

# --- dns: host:false requires servers (unless hosts_file set) ----------------
check "dns host:false no servers no hosts_file" 1 \
    "dns.host: false requires at least dns.servers or dns.hosts_file" \
    "$(cat <<'EOF'
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

# --- egress: is no longer recognized — must produce unknown-field error ------
check "egress key rejected as unknown field" 1 \
    'runner.yml contains unknown field "egress" — your RunSecure version may be older than this config requires' \
    "$(cat <<'EOF'
runtime: node:24
egress:
  - .npmjs.org
EOF
)"

# --- dns.host: true with extra DNS fields → warning, exits 0 ----------------
check_warn "dns.host true with servers emits warning" \
    "WARNING: dns.host: true (default) — dns.servers/hosts_file/whitelist_file/log_queries are ignored" \
    "$(cat <<'EOF'
runtime: node:24
dns:
  host: true
  servers:
    - 8.8.8.8
EOF
)"

# --- dns.servers RFC1918 without hosts_file → warning, exits 0 --------------
check_warn "dns.servers RFC1918 without hosts_file emits warning" \
    "WARNING: dns.servers:" \
    "$(cat <<'EOF'
runtime: node:24
dns:
  host: false
  servers:
    - 10.0.0.53
EOF
)"

# --- http_egress: invalid domain rejected ------------------------------------
check "http_egress with IP rejected" 1 \
    "http_egress entry '192.168.1.1' is invalid" \
    "$(cat <<'EOF'
runtime: node:24
http_egress:
  - 192.168.1.1
EOF
)"

# --- unknown top-level key rejected — exact message per spec §3.3 ------------
check "unknown top-level key rejected" 1 \
    'runner.yml contains unknown field "banana" — your RunSecure version may be older than this config requires' \
    "$(cat <<'EOF'
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
