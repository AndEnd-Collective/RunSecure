#!/bin/bash
# Install the exact Syft and Grype binaries used by release gates. Both the
# installer source and resulting binary are independently checksum-pinned.

set -euo pipefail

INSTALL_DIR=${1:-/usr/local/bin}

SYFT_VERSION=v1.48.0
SYFT_INSTALL_COMMIT=3e2bc6ed095f7ec1a415fb38cfe1c319e95dfed6
SYFT_INSTALL_SHA256=ea054f8b6754db17d34129482ecda1ab733cadab57c1c9202bbe98eb5fe18d24
SYFT_BINARY_SHA256_AMD64=fd260522b9695350ee23483c88b803e96ffe9f8f3954106a7bcad7940a1ade89
SYFT_BINARY_SHA256_ARM64=c0bc05b0d7258a0a2313e063210c191e4549f4073ce5fcde2ebbad40a90c9b23

GRYPE_VERSION=v0.116.0
GRYPE_INSTALL_COMMIT=3b014b00097d43933e5cce485e744db8289a406f
GRYPE_INSTALL_SHA256=8646f06a90b10ca64992c1809b4aa00c44e30b4f551f63c309b0b0ab66873556
GRYPE_BINARY_SHA256_AMD64=766fec22cd9eb84aa5efc854a8bd569305c7d96da4e1dbd7e2940b556c4d21ff
GRYPE_BINARY_SHA256_ARM64=50f9ed107ad4041a76ec6e9b770d4a877c503cedab6cbec99bad40499522cadd

for command_name in curl sha256sum sh; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "ERROR: ${command_name} is required to install scanners" >&2
        exit 1
    }
done

if [[ $(uname -s) != Linux ]]; then
    echo "ERROR: pinned scanner installation supports Linux gates only" >&2
    exit 1
fi
case $(uname -m) in
    x86_64)
        SYFT_BINARY_SHA256=$SYFT_BINARY_SHA256_AMD64
        GRYPE_BINARY_SHA256=$GRYPE_BINARY_SHA256_AMD64
        ;;
    aarch64|arm64)
        SYFT_BINARY_SHA256=$SYFT_BINARY_SHA256_ARM64
        GRYPE_BINARY_SHA256=$GRYPE_BINARY_SHA256_ARM64
        ;;
    *)
        echo "ERROR: unsupported scanner architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

mkdir -p "$INSTALL_DIR"
INSTALL_TMP=$(mktemp -d)
trap 'rm -rf "$INSTALL_TMP"' EXIT

install_scanner() {
    local name=$1
    local version=$2
    local install_commit=$3
    local install_sha256=$4
    local binary_sha256=$5
    local installer=${INSTALL_TMP}/${name}-install.sh
    local binary=${INSTALL_DIR}/${name}

    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        "https://raw.githubusercontent.com/anchore/${name}/${install_commit}/install.sh" \
        --output "$installer"
    printf '%s  %s\n' "$install_sha256" "$installer" | sha256sum -c -

    # Do not let the verified installer fetch and execute another script from
    # a tag. It may fetch the named release asset, whose checksum it verifies,
    # but the only executed installer remains the commit-pinned byte sequence.
    DOWNLOAD_TAG_INSTALL_SCRIPT=false \
        sh "$installer" -b "$INSTALL_DIR" "$version"
    printf '%s  %s\n' "$binary_sha256" "$binary" | sha256sum -c -
    "$binary" version | grep -F "${version#v}" >/dev/null || {
        echo "ERROR: installed ${name} did not report ${version}" >&2
        exit 1
    }
}

install_scanner syft "$SYFT_VERSION" "$SYFT_INSTALL_COMMIT" \
    "$SYFT_INSTALL_SHA256" "$SYFT_BINARY_SHA256"
install_scanner grype "$GRYPE_VERSION" "$GRYPE_INSTALL_COMMIT" \
    "$GRYPE_INSTALL_SHA256" "$GRYPE_BINARY_SHA256"

"${INSTALL_DIR}/syft" version
"${INSTALL_DIR}/grype" version
