#!/bin/bash
# ============================================================================
# RunSecure — Rust Toolchain Pin Contract
# ============================================================================
# Rust was the one toolchain in the repo installed from a floating channel, so
# the image was not reproducible — `--default-toolchain stable` installed
# whatever rustup served that day.
#
# images/rust.Dockerfile now resolves RUST_VERSION=stable to an explicit
# RUST_STABLE_PIN, and .github/workflows/weekly-rust-toolchain.yml is the only
# thing allowed to move it — after re-running the release certification, which
# proves the toolchain from libstd's rustc identity (file-content-cataloger).
#
# Pure file-content checks; no Docker required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PASS=0
FAIL=0

# Results go through a temp file rather than `while read ... < <(python3 <<EOF)`.
# Combining process substitution with a heredoc breaks on bash 3.2 — which is
# what /bin/bash is on macOS, so running this via its shebang silently produced
# zero assertions and still exited 0. A test that reports "PASSED: 0 tests" is
# worse than one that fails.
RESULTS_FILE=$(mktemp)
trap 'rm -f "$RESULTS_FILE"' EXIT

python3 - \
    "${RUNSECURE_ROOT}/images/rust.Dockerfile" \
    "${RUNSECURE_ROOT}/.github/workflows/weekly-rust-toolchain.yml" > "$RESULTS_FILE" <<'PY'
import pathlib
import re
import sys

import yaml

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
    "file-content-cataloger rust" in workflow and "grype-scan-image.sh" in workflow,
    "weekly certification runs the release Grype gate with the rust identity proof",
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
    "steps.verdict.outputs.certified == 'true'" in workflow
    and "rust-certify-verdict.sh certify-results amd64 arm64" in workflow,
    "the pin-bump PR is gated on every architecture's certification verdict",
)

# The release publishes and scans both architectures, so certifying one would
# let an arch-specific regression through to publish. Require both.
doc = yaml.safe_load(workflow)
matrix = (
    doc.get("jobs", {})
    .get("certify", {})
    .get("strategy", {})
    .get("matrix", {})
    .get("include", [])
)
platforms = {entry.get("platform") for entry in matrix}
check(
    platforms == {"linux/amd64", "linux/arm64"},
    f"certification covers every published architecture (got {sorted(p for p in platforms if p)})",
)
check(
    "setup-qemu-action" in workflow,
    "certification sets up QEMU so the non-native arch can actually be built",
)
check(
    doc.get("jobs", {}).get("bump", {}).get("needs") == ["resolve", "certify"],
    "the bump job depends on resolve and certify",
)

# A rejected candidate is a normal outcome and must leave the run green; only
# infrastructure (a build, a missing result) may fail it.
certify_steps = doc.get("jobs", {}).get("certify", {}).get("steps", [])
by_id = {step.get("id"): step for step in certify_steps if step.get("id")}
check(
    all(by_id.get(i, {}).get("continue-on-error") is True for i in ("scan", "hardening")),
    "certification checks record a rejection instead of failing the run",
)
check(
    not any(
        step.get("continue-on-error")
        for step in certify_steps
        if step.get("id") not in ("scan", "hardening")
    ),
    "build and result-recording steps still fail the run on infrastructure errors",
)
uploads = [s for s in certify_steps if "upload-artifact" in str(s.get("uses", ""))]
check(
    len(uploads) == 1 and uploads[0].get("with", {}).get("if-no-files-found") == "error",
    "each certify leg must upload its result",
)
bump_steps = doc.get("jobs", {}).get("bump", {}).get("steps", [])
check(
    any(
        step.get("if") == "needs.certify.result != 'success'" and "exit 1" in step.get("run", "")
        for step in bump_steps
    ),
    "a certify leg that did not complete fails the bump job",
)

for status, message in results:
    print(f"{status}\t{message}")
PY

if [ ! -s "$RESULTS_FILE" ]; then
    echo "FAIL: the assertion script produced no results" >&2
    exit 1
fi

while IFS=$'\t' read -r status message; do
    [ -z "${status:-}" ] && continue
    if [ "$status" = "PASS" ]; then
        echo "  PASS: $message"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $message"
        FAIL=$((FAIL + 1))
    fi
done < "$RESULTS_FILE"

# The weekly resolve step failed every run from 2026-10-11 to 2026-11-01:
# `curl | awk '{...; exit}'` under pipefail killed curl with exit 23 once awk
# stopped reading, so no candidate was ever certified. Run the resolver
# against a manifest shaped like the real one and pin the download-first form.
# record DESCRIPTION COMMAND... — pass when COMMAND succeeds.
record() {
    local desc=$1
    shift
    if "$@"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

# status_of COMMAND... — print the command's exit status, discarding its output.
status_of() {
    "$@" >/dev/null 2>&1
    echo $?
}

RESOLVER="${RUNSECURE_ROOT}/infra/scripts/rust-stable-version.sh"
WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/weekly-rust-toolchain.yml"
MANIFEST_DIR=$(mktemp -d)
trap 'rm -f "$RESULTS_FILE"; rm -rf "$MANIFEST_DIR"' EXIT

{
    printf 'manifest-version = "2"\ndate = "2026-10-30"\n\n'
    printf '[pkg.cargo]\nversion = "1.99.0 (aaaaaaaaa 2026-10-20)"\n\n'
    printf '[pkg.rustc]\nversion = "1.99.1 (bbbbbbbbb 2026-10-28)"\n\n'
    # The real manifest is ~1 MB of per-target tables after [pkg.rustc].
    for i in $(seq 1 20000); do
        printf '[pkg.rust-std.target.t%d]\navailable = true\n' "$i"
    done
} > "${MANIFEST_DIR}/channel.toml"

GOT=$(bash "$RESOLVER" "${MANIFEST_DIR}/channel.toml" 2>/dev/null)
record "resolver reads rustc's version, not cargo's, from a full-size manifest (got '${GOT}')" \
    [ "$GOT" = "1.99.1" ]

printf '[pkg.cargo]\nversion = "1.99.0 (a 2026-10-20)"\n' > "${MANIFEST_DIR}/no-rustc.toml"
record "resolver fails when the manifest has no [pkg.rustc] version" \
    test "$(status_of bash "$RESOLVER" "${MANIFEST_DIR}/no-rustc.toml")" -eq 1

: > "${MANIFEST_DIR}/empty.toml"
record "resolver fails on an empty manifest" \
    test "$(status_of bash "$RESOLVER" "${MANIFEST_DIR}/empty.toml")" -eq 1

record "resolver fails when the manifest was not downloaded" \
    test "$(status_of bash "$RESOLVER" "${MANIFEST_DIR}/absent.toml")" -eq 1

VERDICT="${RUNSECURE_ROOT}/infra/scripts/rust-certify-verdict.sh"
verdict() {
    local dir=$1
    shift
    bash "$VERDICT" "$dir" "$@" 2>/dev/null
}
mkdir -p "${MANIFEST_DIR}/v-pass" "${MANIFEST_DIR}/v-reject" "${MANIFEST_DIR}/v-missing" "${MANIFEST_DIR}/v-bad"
echo pass > "${MANIFEST_DIR}/v-pass/certify-result-amd64"
echo pass > "${MANIFEST_DIR}/v-pass/certify-result-arm64"
echo pass > "${MANIFEST_DIR}/v-reject/certify-result-amd64"
echo "fail: grype-gate-and-rust-inventory" > "${MANIFEST_DIR}/v-reject/certify-result-arm64"
echo pass > "${MANIFEST_DIR}/v-missing/certify-result-amd64"
echo pass > "${MANIFEST_DIR}/v-bad/certify-result-amd64"
echo "maybe" > "${MANIFEST_DIR}/v-bad/certify-result-arm64"

record "verdict certifies only when every architecture passed" \
    [ "$(verdict "${MANIFEST_DIR}/v-pass" amd64 arm64)" = "certified=true" ]

record "verdict rejects the candidate when one architecture failed certification" \
    [ "$(verdict "${MANIFEST_DIR}/v-reject" amd64 arm64)" = "certified=false" ]

record "verdict fails when an architecture reported no result" \
    test "$(status_of verdict "${MANIFEST_DIR}/v-missing" amd64 arm64)" -eq 1

record "verdict fails on a malformed result" \
    test "$(status_of verdict "${MANIFEST_DIR}/v-bad" amd64 arm64)" -eq 1

record "weekly workflow resolves from the downloaded manifest" \
    grep -Fq "CANDIDATE=\$(bash infra/scripts/rust-stable-version.sh \"\$MANIFEST\")" "$WORKFLOW"
record "weekly workflow downloads the manifest to a file" \
    grep -Fq "curl --proto '=https' --tlsv1.2 -sSf -o \"\$MANIFEST\"" "$WORKFLOW"

record "weekly workflow does not pipe the channel manifest download into a parser" \
    test "$(grep -A2 'channel-rust-stable.toml' "$WORKFLOW" | grep -c '^ *|')" -eq 0

echo ""
echo "=== Rust Toolchain Pin Contract ==="
echo ""
if [ "$PASS" -eq 0 ]; then
    echo "FAILED: no assertions ran"
    exit 1
fi
if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
