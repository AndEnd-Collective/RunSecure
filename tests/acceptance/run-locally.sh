#!/bin/bash
# ============================================================================
# RunSecure — Local Acceptance Driver
# ============================================================================
# Runs the same acceptance suite as the post-publish CI workflow, but
# against either local or published images.
#
# Usage:
#   # Test the LOCAL build of node:24:
#   ./tests/acceptance/run-locally.sh node 24
#
#   # Test a SPECIFIC published version:
#   IMAGE_VERSION=1.1.2 ./tests/acceptance/run-locally.sh python 3.12
#
# Local mode (default) builds runner-base + the language image first.
# Published mode (IMAGE_VERSION set) pulls from GHCR.
# ============================================================================

set -euo pipefail

LANG="${1:-node}"
LANG_VERSION="${2:-24}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

case "$LANG" in
    node|python|rust) ;;
    *) echo "ERROR: lang must be node|python|rust (got: $LANG)" >&2; exit 2 ;;
esac

if [ -z "${IMAGE_VERSION:-}" ]; then
    echo "[run-locally] LOCAL mode — building images first"
    cd "$RUNSECURE_ROOT"
    docker build -f infra/squid/Dockerfile -t "ghcr.io/andend-collective/runsecure/proxy:local-test" infra/squid/
    docker build -f images/base.Dockerfile -t runner-base:latest .
    case "$LANG" in
        node)   ARG="NODE_VERSION=$LANG_VERSION"   ;;
        python) ARG="PYTHON_VERSION=$LANG_VERSION" ;;
        rust)   ARG="RUST_VERSION=$LANG_VERSION"   ;;
    esac
    docker build -f "images/${LANG}.Dockerfile" --build-arg "$ARG" \
        -t "ghcr.io/andend-collective/runsecure/${LANG}:local-test-${LANG_VERSION}" .
    export IMAGE_VERSION="local-test"
else
    echo "[run-locally] PUBLISHED mode — using IMAGE_VERSION=${IMAGE_VERSION}"
fi

export LANG LANG_VERSION

cd "$SCRIPT_DIR"
trap 'docker compose -f docker-compose.acceptance.yml down -v 2>/dev/null || true' EXIT
docker compose -f docker-compose.acceptance.yml up \
    --abort-on-container-exit --exit-code-from runner
