#!/bin/bash
# Re-fetch an annotated release tag and the remote's current main branch. Prove
# the tag resolves to the immutable build under release and that build is
# already reachable from merged main.

set -euo pipefail

usage() {
    echo "Usage: $0 REMOTE TAG EXPECTED_BUILD_SHA" >&2
    exit 2
}

[[ $# -eq 3 ]] || usage

REMOTE=$1
TAG=$2
EXPECTED_BUILD_SHA=$3

[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "ERROR: release tag is not exact semver: $TAG" >&2
    exit 1
}
[[ "$EXPECTED_BUILD_SHA" =~ ^[0-9a-f]{40,64}$ ]] || {
    echo "ERROR: expected build SHA is invalid" >&2
    exit 1
}

# Fetch only the named tag. --force prevents a stale local tag from hiding a
# remote change; the expected build SHA check below still fails closed.
git fetch --force --no-tags "$REMOTE" \
    "refs/tags/${TAG}:refs/tags/${TAG}"
MAIN_SNAPSHOT_REF=refs/runsecure/release-main
git fetch --force --no-tags "$REMOTE" \
    "refs/heads/main:${MAIN_SNAPSHOT_REF}"

LOCAL_PEELED=$(git rev-parse "refs/tags/${TAG}^{}")
if [[ "$LOCAL_PEELED" != "$EXPECTED_BUILD_SHA" ]]; then
    echo "ERROR: fetched ${TAG} peels to ${LOCAL_PEELED}, expected ${EXPECTED_BUILD_SHA}" >&2
    exit 1
fi

REMOTE_PEELED_LINES=$(git ls-remote --tags "$REMOTE" "refs/tags/${TAG}^{}")
if [[ $(printf '%s\n' "$REMOTE_PEELED_LINES" | sed '/^$/d' | wc -l | tr -d ' ') -ne 1 ]]; then
    echo "ERROR: remote ${TAG} is missing, ambiguous, or not annotated" >&2
    exit 1
fi
REMOTE_PEELED=$(printf '%s\n' "$REMOTE_PEELED_LINES" | awk '{print $1}')
if [[ "$REMOTE_PEELED" != "$EXPECTED_BUILD_SHA" ]]; then
    echo "ERROR: remote ${TAG} peels to ${REMOTE_PEELED}, expected ${EXPECTED_BUILD_SHA}" >&2
    exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BUILD_SHA" "$MAIN_SNAPSHOT_REF"; then
    echo "ERROR: ${TAG} build ${EXPECTED_BUILD_SHA} is not reachable from remote main" >&2
    exit 1
fi

echo "Verified ${REMOTE} ${TAG} -> ${EXPECTED_BUILD_SHA} on merged main"
