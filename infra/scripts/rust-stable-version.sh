#!/bin/bash
# Print the rustc version from a downloaded rust stable channel manifest
# (channel-rust-stable.toml). The manifest's top-level `version` is cargo's, so
# read the [pkg.rustc] table instead.
#
# Takes a file, not a pipe: awk stops at the first match, and under pipefail a
# `curl | awk` producer that is still writing dies with curl exit 23.

set -euo pipefail

[[ $# -eq 1 ]] || {
    echo "Usage: $0 CHANNEL_MANIFEST" >&2
    exit 2
}

MANIFEST=$1
[[ -s "$MANIFEST" ]] || {
    echo "ERROR: channel manifest is missing or empty: $MANIFEST" >&2
    exit 1
}

VERSION=$(awk '/^\[pkg\.rustc\]/{f=1} f&&/^version = /{print $3; exit}' "$MANIFEST" | tr -d '"')
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "ERROR: no concrete rustc version in $MANIFEST (got '${VERSION}')" >&2
    exit 1
}

echo "$VERSION"
