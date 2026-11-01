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
OVERRIDE=''
PLATFORM=''
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
    arg=${args[$index]}
    case "$arg" in
        syft-json=*) OUTPUT="${arg#syft-json=}" ;;
        --select-catalogers=*) SELECTION="${arg#*=}"; printf 'selection=%s\n' "$SELECTION" >>"$FAKE_LOG" ;;
        --platform)
            index=$((index + 1))
            PLATFORM=${args[$index]}
            ;;
        --override-default-catalogers)
            index=$((index + 1))
            OVERRIDE=${args[$index]}
            printf 'override=%s\n' "$OVERRIDE" >>"$FAKE_LOG"
            ;;
    esac
done
printf 'platform=%s\n' "${PLATFORM:-default}" >>"$FAKE_LOG"
[[ -n "$OUTPUT" ]]
# file-content-cataloger: libstd captured from the image. FAKE_RUST_MODE picks
# the toolchain directory and the bytes rustc embedded in it.
if [[ "$OVERRIDE" == file-content-cataloger ]]; then
    TOOLCHAIN=1.99.1-aarch64-unknown-linux-gnu
    IDENTITY='rustc version 1.99.1 (58cf8f9c3 2026-10-13)'
    case "${FAKE_RUST_MODE:-good}" in
        good) ;;
        mismatch) TOOLCHAIN=1.98.0-aarch64-unknown-linux-gnu ;;
        no-identity) IDENTITY='rustc 1.99.1' ;;
        two-identities) IDENTITY='rustc version 1.99.1 (58cf8f9c3 2026-10-13)\000rustc version 1.97.1 (8bab26f4f 2026-07-14)' ;;
        absent)
            printf '%s\n' '{"artifacts":[],"files":[],"descriptor":{"configuration":{"catalogers":{"used":["file-content-cataloger"]}}}}' >"$OUTPUT"
            exit 0
            ;;
    esac
    CONTENTS=$(printf "\177ELF\000\000GCC: (GNU) 9.5.0\000${IDENTITY}\000\377\376" | base64 | tr -d '\n')
    printf '{"artifacts":[],"files":[{"location":{"path":"/home/runner/.rustup/toolchains/%s/lib/rustlib/aarch64-unknown-linux-gnu/lib/libstd-f9f1a1f02cfcb825.so"},"contents":"%s"}],"descriptor":{"configuration":{"catalogers":{"used":["file-content-cataloger","file-metadata-cataloger"]}}}}\n' \
        "$TOOLCHAIN" "$CONTENTS" >"$OUTPUT"
    exit 0
fi
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

: >"$FAKE_LOG"
PLATFORM_SARIF="${TEST_TMP}/arm64.sarif"
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    FAKE_PRESENCE_MODE=good bash "$SCANNER" --platform linux/arm64 \
    image:test "$PLATFORM_SARIF" ca-certificates '' '' \
    binary-classifier-cataloger rust >/dev/null 2>&1; then
    pass "explicit image platform passes"
else
    fail "explicit image platform should pass"
fi
if [[ $(grep -Fxc 'platform=linux/arm64' "$FAKE_LOG") -eq 2 ]]; then
    pass "policy and runtime-presence inventories use the requested platform"
else
    fail "every Syft inventory must use the requested platform"
fi

PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    bash "$SCANNER" --platform linux/s390x image:test \
    "${TEST_TMP}/unsupported-platform.sarif" >/dev/null 2>&1
platform_status=$?
if [[ $platform_status -eq 2 ]]; then
    pass "unsupported image platform exits 2"
else
    fail "unsupported image platform must exit 2"
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

# --- rust toolchain identity (file-content-cataloger:rust) -----------------
rust_presence() {
    PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
        FAKE_RUST_MODE="$1" bash "$SCANNER" --platform linux/arm64 image:test \
        "${TEST_TMP}/rust-$1.sarif" ca-certificates '' '' \
        file-content-cataloger rust >"${TEST_TMP}/rust-$1.out" 2>&1
}
: >"$FAKE_LOG"
if rust_presence good; then
    pass "rust toolchain identity in libstd proves presence"
else
    fail "rust toolchain identity in libstd should pass"
fi
if grep -Fq 'Rust toolchain present: rustc version 1.99.1 (58cf8f9c3 2026-10-13)' "${TEST_TMP}/rust-good.out"; then
    pass "rust identity proof reports the exact toolchain"
else
    fail "rust identity proof did not report the toolchain"
fi
if grep -Fxq 'override=file-content-cataloger' "$FAKE_LOG" \
    && [[ $(grep -Fxc 'platform=linux/arm64' "$FAKE_LOG") -eq 2 ]]; then
    pass "rust identity is read by Syft alone from the requested platform"
else
    fail "rust identity must come from a file-content-only Syft run on the requested platform"
fi
if grep -Eq '^grype=.*presence\.syft\.json' "$FAKE_LOG"; then
    fail "rust identity inventory must never feed Grype"
else
    pass "rust identity inventory is isolated from Grype"
fi
for mode in absent no-identity two-identities mismatch; do
    if rust_presence "$mode"; then
        fail "rust identity proof must fail closed: ${mode}"
    else
        pass "rust identity proof fails closed: ${mode}"
    fi
done
if PATH="${FAKE_BIN}:$PATH" FAKE_LOG="$FAKE_LOG" FAKE_SBOM_MODE=good \
    bash "$SCANNER" image:test "${TEST_TMP}/fc-python.sarif" ca-certificates \
    '' '' file-content-cataloger python >/dev/null 2>&1; then
    fail "file-content presence must be limited to rust"
else
    pass "file-content presence is limited to rust"
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
