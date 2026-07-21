#!/bin/bash
# Behavioral tests for the explicit Syft -> Grype image policy.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCANNER="${RUNSECURE_ROOT}/infra/scripts/grype-scan-image.sh"
TEST_TMP=$(mktemp -d)
FAKE_BIN="${TEST_TMP}/bin"
FAKE_LOG="${TEST_TMP}/calls.log"
mkdir -p "$FAKE_BIN"
trap 'rm -rf "$TEST_TMP"' EXIT

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

cat >"${FAKE_BIN}/syft" <<'EOF'
#!/bin/bash
set -euo pipefail
OUTPUT=''
SELECTION=''
for arg in "$@"; do
    case "$arg" in
        syft-json=*) OUTPUT="${arg#syft-json=}" ;;
        --select-catalogers=*) SELECTION="${arg#*=}"; printf 'selection=%s\n' "$SELECTION" >>"$FAKE_LOG" ;;
    esac
done
[[ -n "$OUTPUT" ]]
if [[ "$SELECTION" == +binary-classifier-cataloger ]]; then
    if [[ "${FAKE_PRESENCE_MODE:-good}" == good ]]; then
        printf '%s\n' '{
          "artifacts":[{"name":"rust","type":"binary","foundBy":"binary-classifier-cataloger","locations":[{"path":"/home/runner/.rustup/toolchains/stable/bin/rustc"}]}],
          "descriptor":{"configuration":{"catalogers":{"used":["binary-classifier-cataloger"]}}}
        }' >"$OUTPUT"
    else
        printf '%s\n' '{"artifacts":[],"descriptor":{"configuration":{"catalogers":{"used":["binary-classifier-cataloger"]}}}}' >"$OUTPUT"
    fi
    exit 0
fi
case "${FAKE_SBOM_MODE:-good}" in
    good)
        printf '%s\n' '{
          "artifacts": [
            {"name":"ca-certificates","type":"deb","foundBy":"dpkg-db-cataloger","locations":[{"path":"/var/lib/dpkg/status"}]},
            {"name":"pip","type":"python","foundBy":"python-installed-package-cataloger","locations":[{"path":"/opt/python/site-packages"}]}
          ],
          "descriptor":{"configuration":{"catalogers":{"used":["cargo-auditable-binary-cataloger","dotnet-deps-binary-cataloger","dpkg-db-cataloger","go-module-binary-cataloger","javascript-package-cataloger","python-installed-package-cataloger"]}}}
        }' >"$OUTPUT"
        ;;
    no-dpkg)
        printf '%s\n' '{
          "artifacts":[{"name":"pip","type":"python","foundBy":"python-installed-package-cataloger","locations":[{"path":"/opt/python/site-packages"}]}],
          "descriptor":{"configuration":{"catalogers":{"used":["cargo-auditable-binary-cataloger","dotnet-deps-binary-cataloger","dpkg-db-cataloger","go-module-binary-cataloger","javascript-package-cataloger","python-installed-package-cataloger"]}}}
        }' >"$OUTPUT"
        ;;
    no-ecosystem)
        printf '%s\n' '{
          "artifacts":[{"name":"ca-certificates","type":"deb","foundBy":"dpkg-db-cataloger","locations":[{"path":"/var/lib/dpkg/status"}]}],
          "descriptor":{"configuration":{"catalogers":{"used":["cargo-auditable-binary-cataloger","dotnet-deps-binary-cataloger","dpkg-db-cataloger","go-module-binary-cataloger","javascript-package-cataloger","python-installed-package-cataloger"]}}}
        }' >"$OUTPUT"
        ;;
    missing-retained)
        printf '%s\n' '{
          "artifacts":[{"name":"ca-certificates","type":"deb","foundBy":"dpkg-db-cataloger","locations":[{"path":"/var/lib/dpkg/status"}]}],
          "descriptor":{"configuration":{"catalogers":{"used":["dpkg-db-cataloger"]}}}
        }' >"$OUTPUT"
        ;;
    raw)
        printf '%s\n' '{
          "artifacts":[{"name":"curl","type":"binary","foundBy":"binary-classifier-cataloger","locations":[{"path":"/usr/bin/curl"}]}],
          "descriptor":{"configuration":{"catalogers":{"used":["binary-classifier-cataloger"]}}}
        }' >"$OUTPUT"
        ;;
    empty)
        printf '%s\n' '{"artifacts":[],"descriptor":{"configuration":{"catalogers":{"used":[]}}}}' >"$OUTPUT"
        ;;
esac
EOF

cat >"${FAKE_BIN}/grype" <<'EOF'
#!/bin/bash
set -euo pipefail
TARGET="$1"
shift
OUTPUT=''
FILE=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --file) FILE="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'grype=%s:%s\n' "$OUTPUT" "$TARGET" >>"$FAKE_LOG"
if [[ "$OUTPUT" == sarif ]]; then
    if [[ "${FAKE_GRYPE_SARIF_FAIL:-0}" == 1 ]]; then
        exit 1
    fi
    printf '%s\n' '{"version":"2.1.0","runs":[]}' >"$FILE"
fi
if [[ "$OUTPUT" == table && "${FAKE_GRYPE_GATE_FAIL:-0}" == 1 ]]; then
    exit 1
fi
EOF

chmod 0555 "${FAKE_BIN}/syft" "${FAKE_BIN}/grype"

GOOD_SARIF="${TEST_TMP}/good.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    bash "$SCANNER" image:test "$GOOD_SARIF" ca-certificates \
    python-installed-package-cataloger pip >/dev/null 2>&1; then
    pass "ecosystem-aware inventory passes"
else
    fail "ecosystem-aware inventory should pass"
fi

EXPECTED_SELECTION='-binary-classifier-cataloger,-elf-binary-package-cataloger,-pe-binary-package-cataloger'
if grep -Fxq "selection=${EXPECTED_SELECTION}" "$FAKE_LOG"; then
    pass "only generic raw-binary classifiers are excluded"
else
    fail "cataloger exclusion set drifted"
fi

TABLE_TARGET=$(awk -F: '/^grype=table:/{print substr($0, index($0, "sbom:")); exit}' "$FAKE_LOG")
SARIF_TARGET=$(awk -F: '/^grype=sarif:/{print substr($0, index($0, "sbom:")); exit}' "$FAKE_LOG")
if [[ -n "$TABLE_TARGET" && "$TABLE_TARGET" == "$SARIF_TARGET" && -f "$GOOD_SARIF" ]]; then
    pass "blocking table and SARIF consume one exact SBOM"
else
    fail "table and SARIF did not consume one exact SBOM"
fi

PRESENCE_SARIF="${TEST_TMP}/presence.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    FAKE_PRESENCE_MODE=good bash "$SCANNER" image:test "$PRESENCE_SARIF" \
    ca-certificates '' '' binary-classifier-cataloger rust >/dev/null 2>&1; then
    pass "separate exact runtime presence inventory passes"
else
    fail "runtime presence inventory should pass"
fi
if grep -Fxq 'selection=+binary-classifier-cataloger' "$FAKE_LOG"; then
    pass "runtime presence uses the one explicit supplemental cataloger"
else
    fail "runtime presence cataloger selection drifted"
fi
if grep -Eq '^grype=.*presence\.syft\.json' "$FAKE_LOG"; then
    fail "generic runtime presence inventory must never feed Grype"
else
    pass "generic runtime presence inventory is isolated from Grype"
fi
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    FAKE_PRESENCE_MODE=missing bash "$SCANNER" image:test \
    "${TEST_TMP}/missing-presence.sarif" ca-certificates '' '' \
    binary-classifier-cataloger rust >/dev/null 2>&1; then
    fail "missing exact runtime presence should fail closed"
else
    pass "missing exact runtime presence fails closed"
fi

RAW_SARIF="${TEST_TMP}/raw.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=raw \
    bash "$SCANNER" image:test "$RAW_SARIF" >/dev/null 2>&1; then
    fail "generic raw-binary inventory should fail closed"
else
    pass "generic raw-binary inventory fails closed"
fi

EMPTY_SARIF="${TEST_TMP}/empty.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=empty \
    bash "$SCANNER" image:test "$EMPTY_SARIF" >/dev/null 2>&1; then
    fail "empty inventory should fail closed"
else
    pass "empty inventory fails closed"
fi

if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=no-dpkg \
    bash "$SCANNER" image:test "${TEST_TMP}/no-dpkg.sarif" ca-certificates \
    python-installed-package-cataloger pip >/dev/null 2>&1; then
    fail "missing expected dpkg package should fail closed"
else
    pass "missing expected dpkg package fails closed"
fi

if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=no-ecosystem \
    bash "$SCANNER" image:test "${TEST_TMP}/no-ecosystem.sarif" ca-certificates \
    python-installed-package-cataloger pip >/dev/null 2>&1; then
    fail "missing expected ecosystem package should fail closed"
else
    pass "missing expected ecosystem package fails closed"
fi

if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=missing-retained \
    bash "$SCANNER" image:test "${TEST_TMP}/missing-retained.sarif" \
    ca-certificates >/dev/null 2>&1; then
    fail "disabled retained catalogers should fail closed"
else
    pass "disabled retained catalogers fail closed"
fi

FAILED_SARIF="${TEST_TMP}/failed.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    FAKE_GRYPE_GATE_FAIL=1 bash "$SCANNER" image:test "$FAILED_SARIF" \
    ca-certificates python-installed-package-cataloger pip >/dev/null 2>&1; then
    fail "HIGH/fixed Grype result should fail"
elif [[ -f "$FAILED_SARIF" ]]; then
    pass "HIGH/fixed result fails after preserving SARIF"
else
    fail "failed gate did not preserve SARIF"
fi

if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    FAKE_GRYPE_SARIF_FAIL=1 bash "$SCANNER" image:test \
    "${TEST_TMP}/sarif-error.sarif" ca-certificates \
    python-installed-package-cataloger pip >/dev/null 2>&1; then
    fail "SARIF generation failure should fail"
else
    pass "SARIF generation failure fails closed"
fi

if bash "$SCANNER" >/dev/null 2>&1; [[ $? -eq 2 ]]; then
    pass "invalid usage exits 2"
else
    fail "invalid usage must exit 2"
fi

echo ""
echo "=== Grype Scan Policy Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
[[ $FAIL -eq 0 ]]
