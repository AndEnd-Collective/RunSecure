#!/bin/bash
# ============================================================================
# RunSecure — verify build provenance for every image in a release manifest
# ============================================================================
# publish-images.yml attests each image it pushes: a SLSA build-provenance
# statement, signed keyless through Sigstore with the workflow's own OIDC
# identity and bound to the pushed digest. This script is the other half. It
# runs before any tag a consumer pulls (`nightly`, `<version>`, `latest`) is
# moved, and refuses unless every image in the manifest has provenance that
# says:
#
#   - it was signed by publish-images.yml in this repository,
#   - on a GitHub-hosted runner,
#   - from the expected git ref (the release tag, or main for a nightly),
#   - at the expected commit.
#
# One image without matching provenance fails the whole run. Nothing is
# retagged by this script.
#
# Usage: verify-image-provenance.sh MANIFEST REPOSITORY SOURCE_REF BUILD_SHA
#   MANIFEST     release-images.json produced by the Publish Images run
#   REPOSITORY   owner/repo that must have signed the images
#   SOURCE_REF   e.g. refs/tags/v3.1.0 or refs/heads/main
#   BUILD_SHA    commit the images must have been built from
#
# Requires: gh (authenticated), jq.
# ============================================================================

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: verify-image-provenance.sh MANIFEST REPOSITORY SOURCE_REF BUILD_SHA" >&2
    exit 2
fi
MANIFEST="$1"
REPOSITORY="$2"
SOURCE_REF="$3"
BUILD_SHA="$4"

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "::error::invalid repository '${REPOSITORY}'" >&2
    exit 2
fi
if [[ ! "$SOURCE_REF" =~ ^refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$ ]]; then
    echo "::error::source ref must be a release tag or main, got '${SOURCE_REF}'" >&2
    exit 2
fi
if [[ ! "$BUILD_SHA" =~ ^[0-9a-f]{40,64}$ ]]; then
    echo "::error::invalid build SHA '${BUILD_SHA}'" >&2
    exit 2
fi

REFERENCE='^ghcr\.io/andend-collective/runsecure/[a-z0-9-]+@sha256:[0-9a-f]{64}$'
references=()
while IFS= read -r reference; do
    if [[ ! "$reference" =~ $REFERENCE ]]; then
        echo "::error::manifest entry is not an immutable RunSecure image reference: ${reference}" >&2
        exit 1
    fi
    references+=("$reference")
done < <(jq -r '.images | to_entries | sort_by(.key) | .[].value' "$MANIFEST")

if [[ ${#references[@]} -eq 0 ]]; then
    echo "::error::manifest ${MANIFEST} lists no images" >&2
    exit 1
fi

failed=0
for reference in "${references[@]}"; do
    if gh attestation verify "oci://${reference}" \
        --repo "$REPOSITORY" \
        --signer-workflow "${REPOSITORY}/.github/workflows/publish-images.yml" \
        --source-ref "$SOURCE_REF" \
        --source-digest "$BUILD_SHA" \
        --deny-self-hosted-runners >/dev/null; then
        echo "provenance verified: ${reference}"
    else
        echo "::error title=Provenance verification failed::${reference} has no build provenance signed by ${REPOSITORY}/.github/workflows/publish-images.yml for ${SOURCE_REF} at ${BUILD_SHA}"
        failed=$((failed + 1))
    fi
done

if [[ $failed -gt 0 ]]; then
    echo "::error::${failed} of ${#references[@]} images failed provenance verification; no tag was moved."
    exit 1
fi
echo "All ${#references[@]} images carry verified build provenance."
