#!/bin/bash
# Install the exact Syft and Grype binaries used by release gates. Both the
# installer source and resulting binary are independently checksum-pinned.

set -euo pipefail

INSTALL_DIR=${1:-/usr/local/bin}

SYFT_VERSION=v1.55.0
SYFT_INSTALL_COMMIT=f15c3343e29dfb20cf6d82c820e7090b49808c96
SYFT_INSTALL_SHA256=787fe2aa12311f7dd8e1d9337dfc6e25f091396c958937293a2d3c0eca2ff8ce
SYFT_BINARY_SHA256_AMD64=64c9631c3560336c55c549df0de08cd577d02399c9de807ac390960a4ed5c351
SYFT_BINARY_SHA256_ARM64=4f8068b25551a42991a292a42078519fdc739a97a6f6310e1dcf1367a258c1c2

GRYPE_VERSION=v0.121.0
GRYPE_INSTALL_COMMIT=afe2742527d98d822da06c9f32eed86fe3d193e0
GRYPE_INSTALL_SHA256=4bc8e844d1ca0b74082cb51e1587d58c35150756954660db3d3078e57c81cbfd
GRYPE_BINARY_SHA256_AMD64=bd511334178bc3002eb9eb58880f89e01e35f7fed7cfbe671171127a8afa3596
GRYPE_BINARY_SHA256_ARM64=e81fd2b6669c5a9ab7fee756e63e769cc40163310c11e546420b4d93e2118543

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
