#!/bin/bash
# ============================================================================
# RunSecure — TCP Egress Deprecation Tests (host-side, no Docker)
# ============================================================================
# Tests that the old 'egress:' key is accepted for backward compatibility
# (with a deprecation note) while the new 'http_egress:' key is preferred.
# Also tests that mixing old + new keys is handled correctly.
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
    if [[ -n "$expected_pattern" ]] && ! echo "$output" | grep -qF "$expected_pattern"; then
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

# --- Old 'egress' key still accepted (backward compat) ----------------------
check "old egress key accepted" 0 "" "$(cat <<'EOF'
runtime: node:24
egress:
  - .neon.tech
  - api.vercel.com
EOF
)"

# --- New 'http_egress' key preferred ----------------------------------------
check "new http_egress key accepted" 0 "" "$(cat <<'EOF'
runtime: node:24
http_egress:
  - .neon.tech
  - api.vercel.com
EOF
)"

# --- Both egress and http_egress → error (per spec: pick one) ---------------
check "both egress and http_egress is an error" 1 \
    "http_egress and egress (deprecated) both set — pick one" \
    "$(cat <<'EOF'
runtime: node:24
egress:
  - .neon.tech
http_egress:
  - api.vercel.com
EOF
)"

# --- Old egress with tcp_egress -------------------------------------------------
check "old egress + new tcp_egress accepted" 0 "" "$(cat <<'EOF'
runtime: node:24
egress:
  - .neon.tech
tcp_egress:
  - ep-foo.neon.tech:5432
EOF
)"

# --- New http_egress with tcp_egress ------------------------------------------
check "new http_egress + tcp_egress accepted" 0 "" "$(cat <<'EOF'
runtime: node:24
http_egress:
  - .neon.tech
tcp_egress:
  - ep-foo.neon.tech:5432
EOF
)"

# --- Print results -----------------------------------------------------------
echo ""
echo "=== TCP Egress Deprecation Tests ==="
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
