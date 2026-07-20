#!/bin/bash
# ============================================================================
# RunSecure — Scanner Package Inventory Validation
# ============================================================================
# Proves that terminal hardening preserves only enough inert dpkg inventory
# for scanners to identify language-layer Debian packages. Syft must catalogue
# the expected package from /var/lib/dpkg/status, then Grype must consume that
# exact SBOM successfully. Vulnerability presence is intentionally not asserted:
# a fully patched package can legitimately have no Grype matches.
#
# Usage:
#   bash tests/validation/test-scanner-package-inventory.sh \
#     [image-ref] [expected-package]
#
# Defaults: runner-node:24, nodejs
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_REF="${1:-runner-node:24}"
EXPECTED_PACKAGE="${2:-nodejs}"

SYFT_FALLBACK='anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c'
GRYPE_FALLBACK='anchore/grype:v0.116.0@sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821'

TEST_TMP=$(mktemp -d "${RUNSECURE_ROOT}/.scanner-test.XXXXXX")
SBOM_JSON="${TEST_TMP}/sbom.json"
GRYPE_JSON="${TEST_TMP}/grype.json"

cleanup() {
    rm -f "$SBOM_JSON" "$GRYPE_JSON"
    rmdir "$TEST_TMP" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
docker image inspect "$IMAGE_REF" >/dev/null 2>&1 \
    || fail "image not found: $IMAGE_REF"

echo "Cataloguing ${IMAGE_REF} with Syft..."
if command -v syft >/dev/null 2>&1; then
    syft "docker:${IMAGE_REF}" -o json >"$SBOM_JSON"
else
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        "$SYFT_FALLBACK" "docker:${IMAGE_REF}" -o json >"$SBOM_JSON"
fi

PACKAGE_RECORD=$(jq -cer --arg package "$EXPECTED_PACKAGE" '
    first(
        .artifacts[]
        | select(
            .name == $package
            and .type == "deb"
            and .foundBy == "dpkg-db-cataloger"
            and (.purl | startswith("pkg:deb/"))
            and any(.locations[]?; .path == "/var/lib/dpkg/status")
        )
        | {name, version, type, foundBy, purl}
    )
' "$SBOM_JSON") \
    || fail "Syft did not catalogue ${EXPECTED_PACKAGE} as a Debian package from /var/lib/dpkg/status"

echo "Syft package evidence: ${PACKAGE_RECORD}"
echo "Scanning the exact Syft SBOM with Grype..."
if command -v grype >/dev/null 2>&1; then
    grype "sbom:${SBOM_JSON}" -o json >"$GRYPE_JSON"
else
    docker run --rm \
        -v "${TEST_TMP}:/work:ro" \
        "$GRYPE_FALLBACK" "sbom:/work/sbom.json" -o json >"$GRYPE_JSON"
fi

jq -e --arg image "$IMAGE_REF" '
    .descriptor.name == "grype"
    and .source.type == "image"
    and .source.target.userInput == $image
' \
    "$GRYPE_JSON" >/dev/null \
    || fail "Grype did not report the expected image source after SBOM ingestion"

echo "PASS: Syft catalogued ${EXPECTED_PACKAGE} from read-only dpkg inventory and Grype consumed the SBOM"
