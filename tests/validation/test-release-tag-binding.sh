#!/bin/bash
# Exercise the release tag verifier against a local remote, including moved and
# lightweight tags. No GitHub API or network access is required.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNSECURE_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
VERIFIER=${RUNSECURE_ROOT}/infra/scripts/verify-remote-release-tag.sh
PUBLISH_WORKFLOW=${RUNSECURE_ROOT}/.github/workflows/publish-images.yml
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-tag-binding.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT

git init --bare "${TEST_TMP}/remote.git" >/dev/null
git init -b main "${TEST_TMP}/source" >/dev/null
git -C "${TEST_TMP}/source" config user.name tester
git -C "${TEST_TMP}/source" config user.email tester@example.invalid

printf 'first\n' > "${TEST_TMP}/source/evidence.txt"
git -C "${TEST_TMP}/source" add evidence.txt
git -C "${TEST_TMP}/source" commit -m first >/dev/null
FIRST_SHA=$(git -C "${TEST_TMP}/source" rev-parse HEAD)
git -C "${TEST_TMP}/source" tag -a v1.2.3 -m v1.2.3
git -C "${TEST_TMP}/source" remote add origin "${TEST_TMP}/remote.git"
git -C "${TEST_TMP}/source" push -u origin main refs/tags/v1.2.3 >/dev/null
git --git-dir "${TEST_TMP}/remote.git" symbolic-ref HEAD refs/heads/main

git clone "${TEST_TMP}/remote.git" "${TEST_TMP}/consumer" >/dev/null 2>&1
(
    cd "${TEST_TMP}/consumer"
    "$VERIFIER" origin v1.2.3 "$FIRST_SHA" >/dev/null
)

printf 'second\n' >> "${TEST_TMP}/source/evidence.txt"
git -C "${TEST_TMP}/source" add evidence.txt
git -C "${TEST_TMP}/source" commit -m second >/dev/null
SECOND_SHA=$(git -C "${TEST_TMP}/source" rev-parse HEAD)
git -C "${TEST_TMP}/source" tag -f -a v1.2.3 -m moved
git -C "${TEST_TMP}/source" push origin main >/dev/null
git -C "${TEST_TMP}/source" push --force origin refs/tags/v1.2.3 >/dev/null

if (
    cd "${TEST_TMP}/consumer"
    "$VERIFIER" origin v1.2.3 "$FIRST_SHA" >/dev/null 2>&1
); then
    echo "FAIL: verifier accepted a remotely moved tag against the old build" >&2
    exit 1
fi
(
    cd "${TEST_TMP}/consumer"
    "$VERIFIER" origin v1.2.3 "$SECOND_SHA" >/dev/null
)

git -C "${TEST_TMP}/source" tag v1.2.4
git -C "${TEST_TMP}/source" push origin refs/tags/v1.2.4 >/dev/null
if (
    cd "${TEST_TMP}/consumer"
    "$VERIFIER" origin v1.2.4 "$SECOND_SHA" >/dev/null 2>&1
); then
    echo "FAIL: verifier accepted a lightweight release tag" >&2
    exit 1
fi

git -C "${TEST_TMP}/source" switch -c divergent "$FIRST_SHA" >/dev/null
printf 'divergent\n' >> "${TEST_TMP}/source/evidence.txt"
git -C "${TEST_TMP}/source" add evidence.txt
git -C "${TEST_TMP}/source" commit -m divergent >/dev/null
DIVERGENT_SHA=$(git -C "${TEST_TMP}/source" rev-parse HEAD)
git -C "${TEST_TMP}/source" tag -a v1.2.5 -m v1.2.5
git -C "${TEST_TMP}/source" push origin refs/tags/v1.2.5 >/dev/null
if (
    cd "${TEST_TMP}/consumer"
    "$VERIFIER" origin v1.2.5 "$DIVERGENT_SHA" >/dev/null 2>&1
); then
    echo "FAIL: verifier accepted a release build that was not merged to main" >&2
    exit 1
fi

if ! grep -q 'Prove the release tag is already merged to main' "$PUBLISH_WORKFLOW" ||
    ! grep -q 'infra/scripts/verify-remote-release-tag.sh' "$PUBLISH_WORKFLOW"; then
    echo "FAIL: tag-triggered image publication is not bound to the verifier" >&2
    exit 1
fi

echo "PASS: release tags are annotated, exact, immutable, and merged to main"
