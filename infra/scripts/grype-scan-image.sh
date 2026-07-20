#!/bin/bash
# Build one ecosystem-aware Syft SBOM and use that exact inventory for the
# blocking Grype table and SARIF output. Generic ELF/PE/version classifiers are
# deliberately excluded: after terminal hardening removes dpkg ownership files,
# those heuristics duplicate patched distro packages as unqualified upstream
# "binary" artifacts. Precise dpkg, npm, Python, Go, Cargo, and .NET catalogers
# remain enabled.

set -euo pipefail

usage() {
    echo "Usage: $0 IMAGE_REF SARIF_FILE [EXPECTED_DPKG_PACKAGE] [EXPECTED_CATALOGER] [EXPECTED_CATALOGER_PACKAGE]" >&2
    exit 2
}

[[ $# -ge 2 && $# -le 5 ]] || usage

IMAGE_REF="$1"
SARIF_FILE="$2"
EXPECTED_DPKG_PACKAGE="${3:-}"
EXPECTED_CATALOGER="${4:-}"
EXPECTED_CATALOGER_PACKAGE="${5:-}"

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required" >&2
    exit 1
}
command -v syft >/dev/null 2>&1 || {
    echo "ERROR: syft is required" >&2
    exit 1
}
command -v grype >/dev/null 2>&1 || {
    echo "ERROR: grype is required" >&2
    exit 1
}

SCAN_TMP=$(mktemp -d)
SBOM_FILE="${SCAN_TMP}/packages.syft.json"
cleanup() {
    rm -f "$SBOM_FILE"
    rmdir "$SCAN_TMP" 2>/dev/null || true
}
trap cleanup EXIT

CATALOGER_SELECTION='-binary-classifier-cataloger,-elf-binary-package-cataloger,-pe-binary-package-cataloger'

echo "Cataloguing ${IMAGE_REF} with ecosystem-aware Syft catalogers..."
syft "$IMAGE_REF" \
    --select-catalogers="$CATALOGER_SELECTION" \
    --output "syft-json=${SBOM_FILE}"

jq -e '.artifacts | length > 0' "$SBOM_FILE" >/dev/null || {
    echo "ERROR: Syft produced an empty package inventory for ${IMAGE_REF}" >&2
    exit 1
}

jq -e '
    ([
        "binary-classifier-cataloger",
        "elf-binary-package-cataloger",
        "pe-binary-package-cataloger"
    ] as $blocked
    | all(.descriptor.configuration.catalogers.used[]?; . as $used | $blocked | index($used) | not)
    and all(.artifacts[]; .foundBy as $found | $blocked | index($found) | not))
' "$SBOM_FILE" >/dev/null || {
    echo "ERROR: generic raw-binary classifier output entered the policy SBOM" >&2
    exit 1
}

jq -e '
    (.descriptor.configuration.catalogers.used // []) as $used
    | [
        "cargo-auditable-binary-cataloger",
        "dotnet-deps-binary-cataloger",
        "dpkg-db-cataloger",
        "go-module-binary-cataloger",
        "javascript-package-cataloger",
        "python-installed-package-cataloger"
    ] as $required
    | all($required[]; . as $name | any($used[]; . == $name))
' "$SBOM_FILE" >/dev/null || {
    echo "ERROR: a required ecosystem-aware package cataloger was disabled" >&2
    exit 1
}

if [[ -n "$EXPECTED_DPKG_PACKAGE" ]]; then
    jq -e --arg package "$EXPECTED_DPKG_PACKAGE" '
        any(.artifacts[];
            .name == $package
            and .type == "deb"
            and .foundBy == "dpkg-db-cataloger"
            and any(.locations[]?; .path == "/var/lib/dpkg/status")
        )
    ' "$SBOM_FILE" >/dev/null || {
        echo "ERROR: expected dpkg inventory package is missing: ${EXPECTED_DPKG_PACKAGE}" >&2
        exit 1
    }
fi

if [[ -n "$EXPECTED_CATALOGER" ]]; then
    jq -e \
        --arg cataloger "$EXPECTED_CATALOGER" \
        --arg package "$EXPECTED_CATALOGER_PACKAGE" '
        any(.descriptor.configuration.catalogers.used[]?; . == $cataloger)
        and any(.artifacts[];
            .foundBy == $cataloger
            and ($package == "" or .name == $package)
        )
    ' "$SBOM_FILE" >/dev/null || {
        echo "ERROR: expected ecosystem package inventory is missing: ${EXPECTED_CATALOGER}:${EXPECTED_CATALOGER_PACKAGE}" >&2
        exit 1
    }
fi

echo "Scanning the exact Syft package SBOM with Grype..."
GRYPE_FAILED=0
grype "sbom:${SBOM_FILE}" --output table --fail-on high --only-fixed \
    || GRYPE_FAILED=1
grype "sbom:${SBOM_FILE}" --output sarif --file "$SARIF_FILE" --only-fixed

if [[ "$GRYPE_FAILED" -ne 0 ]]; then
    echo "ERROR: Grype found HIGH/CRITICAL ecosystem-aware vulnerabilities with fixes in ${IMAGE_REF}" >&2
    exit 1
fi
