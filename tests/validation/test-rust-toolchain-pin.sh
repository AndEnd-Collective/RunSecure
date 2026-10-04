#!/bin/bash
# ============================================================================
# RunSecure — Rust Toolchain Pin Contract
# ============================================================================
# Rust was the one toolchain in the repo installed from a floating channel.
# Two things went wrong because of that:
#   1. the image was not reproducible — `--default-toolchain stable` installed
#      whatever rustup served that day;
#   2. syft's binary-classifier-cataloger stopped recognising rustc at 1.98.0,
#      so the toolchain silently left the SBOM, rust CVEs became unscannable,
#      and every publish failed closed on
#        ERROR: expected runtime presence inventory is missing:
#               binary-classifier-cataloger:rust
#
# images/rust.Dockerfile now resolves RUST_VERSION=stable to an explicit
# RUST_STABLE_PIN, and .github/workflows/weekly-rust-toolchain.yml is the only
# thing allowed to move it — after re-running the release certification.
#
# Pure file-content checks; no Docker required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PASS=0
FAIL=0

while IFS=$'\t' read -r status message; do
    [ -z "${status:-}" ] && continue
    if [ "$status" = "PASS" ]; then
        echo "  PASS: $message"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $message"
        FAIL=$((FAIL + 1))
    fi
done < <(python3 - \
    "${RUNSECURE_ROOT}/images/rust.Dockerfile" \
    "${RUNSECURE_ROOT}/.github/workflows/weekly-rust-toolchain.yml" <<'PY'
import pathlib
import re
import sys

dockerfile = pathlib.Path(sys.argv[1]).read_text()
workflow = pathlib.Path(sys.argv[2]).read_text()

results = []


def check(ok, message):
    results.append(("PASS" if ok else "FAIL", message))


pin = re.search(r"^ARG RUST_STABLE_PIN=(\S+)$", dockerfile, re.MULTILINE)
check(pin is not None, "rust image pins ARG RUST_STABLE_PIN")
if pin:
    check(
        re.fullmatch(r"\d+\.\d+\.\d+", pin.group(1)) is not None,
        f"RUST_STABLE_PIN is an exact version (got {pin.group(1)}, not a channel)",
    )

# The pin must actually be used: resolve `stable` through it, and install the
# resolved toolchain rather than RUST_VERSION directly.
check(
    '[ "${RUST_VERSION}" = "stable" ]' in dockerfile
    and 'TOOLCHAIN="${RUST_STABLE_PIN}"' in dockerfile,
    "RUST_VERSION=stable resolves to RUST_STABLE_PIN",
)
check(
    '--default-toolchain "${TOOLCHAIN}"' in dockerfile,
    "rustup installs the resolved toolchain, not RUST_VERSION",
)
check(
    "rustup show active-toolchain" in dockerfile
    and 'EXPECTED="${RUST_STABLE_PIN}"' in dockerfile,
    "build asserts the active toolchain matches the resolved pin",
)

# Nothing may reintroduce a floating install.
check(
    '--default-toolchain "${RUST_VERSION}"' not in dockerfile,
    "rustup is not invoked with the raw RUST_VERSION channel",
)

# The weekly workflow is the only sanctioned way to move the pin, and it must
# gate on the same inventory-presence check the release gate uses.
check(
    "binary-classifier-cataloger" in workflow and "grype-scan-image.sh" in workflow,
    "weekly certification runs the release Grype gate with the rust presence check",
)
check(
    "install-pinned-scanners.sh" in workflow,
    "weekly certification uses the checksum-pinned scanners",
)
check(
    "RUST_STABLE_PIN=${CANDIDATE}" in workflow,
    "weekly certification builds the candidate through the pin",
)
check(
    "steps.certify.outcome == 'success'" in workflow,
    "the pin-bump PR is gated on the certification passing",
)

for status, message in results:
    print(f"{status}\t{message}")
PY
)

echo ""
echo "=== Rust Toolchain Pin Contract ==="
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
