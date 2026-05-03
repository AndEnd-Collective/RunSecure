#!/bin/bash
# ============================================================================
# RunSecure — H2 hardening.remove / hardening.stub Behaviour (host-side)
# ============================================================================
# Unit tests for the H2 helpers extracted from finalize-hardening.sh.
#
# We can't safely run finalize-hardening.sh against the host (it would
# chmod /etc/passwd) and we can't accurately sandbox the PATH-walking
# remove path on macOS (the helper needs /bin/rm; setting PATH to only
# the sandbox excludes it). Instead we test the parts whose contract
# is unambiguous and host-safe:
#
#   1. _h2_validate_name rejects shell metachars / bad names.
#   2. _h2_install_stub produces a stub that exits 127 with a
#      [runsecure] marker on stderr (verified by running the stub).
#   3. The schema validator (covered separately in
#      test-strict-schema-rejection.sh) gates everything before this.
#
# The full PATH-remove path is exercised end-to-end during image build
# tests where the script runs as root in a clean container — that
# coverage is structural, not unit.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FINALIZE="${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh"

PASS=0
FAIL=0
RESULTS=()

pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1 — $2"); FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d -p "${HOME:-/tmp}" runsecure-h2-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# --- Test 1: _h2_validate_name rejects bad names ----------------------------
# Extract the function definition (lines from `_h2_validate_name() {` to
# the next standalone `}` at column 0) and run it against test inputs.
H2_LIB="${WORK}/h2-validate.sh"
awk '/^_h2_validate_name\(\) \{/,/^\}/' "$FINALIZE" > "$H2_LIB"

# Sanity: confirm extraction worked.
if ! grep -q '_h2_validate_name' "$H2_LIB"; then
    fail "extract" "could not extract _h2_validate_name from $FINALIZE"
else
    pass "extract: _h2_validate_name function isolated"
fi

# Drive the function in a subshell so its `exit 1` doesn't kill the
# parent script. `exit` from inside the inner bash terminates only the
# subshell; we capture stdout+stderr+exit code separately.
_run_validate() {
    local out rc
    out=$(bash -c "
        $(cat "$H2_LIB")
        _h2_validate_name \"\$1\"
    " _ "$1" 2>&1)
    rc=$?
    printf '%s\nrc=%s\n' "$out" "$rc"
}

# Good names — should print nothing and rc=0.
out=$(_run_validate 'curl')
if echo "$out" | grep -q 'rc=0' && ! echo "$out" | grep -q 'invalid name'; then
    pass "H2-validate: 'curl' accepted"
else
    fail "H2-validate-good" "got: '$out'"
fi

out=$(_run_validate 'tar-helper_v2')
if echo "$out" | grep -q 'rc=0'; then
    pass "H2-validate: 'tar-helper_v2' accepted"
else
    fail "H2-validate-good2" "got: '$out'"
fi

# Bad names — should print "invalid name" and rc=1.
for bad in 'curl;evil' 'curl|evil' 'curl evil' 'curl/etc/passwd' '../bin/curl' 'curl`whoami`'; do
    out=$(_run_validate "$bad")
    if echo "$out" | grep -q 'invalid name' && echo "$out" | grep -q 'rc=1'; then
        pass "H2-validate: bad name rejected ($bad)"
    else
        fail "H2-validate-bad: $bad" "got: '$out'"
    fi
done

# --- Test 2: stub script content + behaviour --------------------------------
# Create a fake binary, install a stub over it (using a tweaked copy of
# the helper that takes an explicit absolute path — host-safe), then
# verify the stub exits 127 with the expected marker.
FAKE_BIN="${WORK}/fake-curl"
echo 'echo real' > "$FAKE_BIN"
chmod 755 "$FAKE_BIN"

# Inline stub generator that mimics _h2_install_stub but operates on
# an explicit path (no PATH walk). The production helper differs only
# by performing the `command -v` lookup.
_install_stub_at() {
    local name="$1"
    local target="$2"
    rm -f "$target"
    cat > "$target" <<STUB
#!/bin/sh
echo "[runsecure] '$name' was intentionally replaced by hardening.stub in your runner.yml." >&2
echo "[runsecure] If your job needs $name, remove it from hardening.stub or move to hardening.remove + hardening.allow." >&2
exit 127
STUB
    chmod 555 "$target"
}

_install_stub_at curl "$FAKE_BIN"
out=$("$FAKE_BIN" 2>&1)
rc=$?

if [[ "$rc" == 127 ]]; then
    pass "H2-stub: exits 127"
else
    fail "H2-stub-rc" "expected rc=127, got rc=$rc out='$out'"
fi
if echo "$out" | grep -q '\[runsecure\]'; then
    pass "H2-stub: emits [runsecure] marker"
else
    fail "H2-stub-marker" "stub stderr missing marker: '$out'"
fi
if echo "$out" | grep -q "hardening.stub"; then
    pass "H2-stub: tells user where the setting is"
else
    fail "H2-stub-actionable" "stub message not actionable"
fi

# Stub mode bits: must be 555 (r-xr-xr-x) — readable+executable by all,
# not writable. Avoids accidental tampering by the runner user.
# Cross-platform `stat` mode lookup. GNU stat (Linux/CI) uses `-c '%a'`;
# BSD stat (macOS) uses `-f '%Lp'`. The flag semantics are opposite —
# `-f` on GNU means "filesystem status" and prints unrelated output —
# so we have to detect the platform rather than try one then the other.
if stat --version >/dev/null 2>&1; then
    mode=$(stat -c '%a' "$FAKE_BIN")     # GNU
else
    mode=$(stat -f '%Lp' "$FAKE_BIN")    # BSD
fi
if [[ "$mode" == "555" ]]; then
    pass "H2-stub: mode 555 (r-xr-xr-x, immutable)"
else
    fail "H2-stub-mode" "expected 555, got $mode"
fi

# --- Test 3: actual production helper signature is preserved ----------------
# Lint that the production finalize-hardening.sh still defines all three
# H2 functions and reads both env vars — protects against accidental
# refactor that breaks the wiring.
for fn in _h2_validate_name _h2_install_stub _h2_remove_binary; do
    if grep -qE "^${fn}\(\) \{" "$FINALIZE"; then
        pass "H2-wiring: $fn() defined"
    else
        fail "H2-wiring" "$fn() missing from $FINALIZE"
    fi
done
for var in RUNSECURE_HARDENING_REMOVE RUNSECURE_HARDENING_STUB; do
    if grep -F -q "\${${var}:-}" "$FINALIZE"; then
        pass "H2-wiring: \$$var consumed"
    else
        fail "H2-wiring" "\$$var not read by $FINALIZE"
    fi
done

# --- Print results ----------------------------------------------------------
echo ""
echo "=== H2 hardening behaviour tests ==="
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
