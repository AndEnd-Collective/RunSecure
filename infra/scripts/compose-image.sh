#!/bin/bash
# ============================================================================
# RunSecure — Image Composer
# ============================================================================
# Reads a project's runner.yml and builds a project-specific Docker image
# by layering tool recipes on top of the appropriate language base image.
#
# The resulting image is tagged with a hash of the configuration so that
# identical configs across projects share the same image (deduplication).
#
# If runner.yml specifies a `version:` field, images are pulled from GHCR
# instead of built locally. Falls back to local build on pull failure.
#
# Usage:
#   ./infra/scripts/compose-image.sh /path/to/project
#   ./infra/scripts/compose-image.sh /path/to/project --force  # rebuild
#
# Requires:
#   - Docker
#   - yq (YAML parser) — brew install yq
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLS_DIR="${RUNSECURE_ROOT}/tools"
IMAGES_DIR="${RUNSECURE_ROOT}/images"
REGISTRY_PREFIX="ghcr.io/andend-collective/runsecure"

# --- Arguments ---------------------------------------------------------------
PROJECT_DIR="${1:?Usage: compose-image.sh /path/to/project [--force]}"
FORCE_REBUILD="${2:-}"

if [[ ! -d "$PROJECT_DIR" ]]; then
    echo "[RunSecure] ERROR: Project directory not found: $PROJECT_DIR"
    exit 1
fi

RUNNER_YML="${PROJECT_DIR}/.github/runner.yml"
if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[RunSecure] ERROR: No .github/runner.yml found in $PROJECT_DIR"
    exit 1
fi

# --- Parse runner.yml --------------------------------------------------------
echo "[RunSecure] Reading config: $RUNNER_YML"

# Run schema validator first — fails-closed on malformed YAML, unknown
# fields, or invalid apt/tcp_egress/dns values. Without this the project
# image build proceeds with whatever yq returns from a broken file
# (silent zero entries) and produces a degraded image.
bash "${SCRIPT_DIR}/lib/validate-schema.sh" "$RUNNER_YML"

# Local fail-closed yq wrapper — same pattern as validate-schema.sh.
_yq() {
    local expr="$1"
    local file="$2"
    local out
    local err_file
    err_file=$(mktemp /tmp/runsecure-yq-err-XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -f '${err_file}'" RETURN
    if ! out=$(yq "$expr" "$file" 2>"$err_file"); then
        echo "[RunSecure] ERROR: yq failed parsing $file (expression: $expr): $(cat "$err_file")" >&2
        exit 1
    fi
    printf '%s\n' "$out"
}

RUNTIME=$(_yq '.runtime' "$RUNNER_YML")
TOOLS=$(_yq '.tools // [] | .[]' "$RUNNER_YML")
APT_PACKAGES=$(_yq '.apt // [] | .[]' "$RUNNER_YML")
RUNSECURE_VERSION=$(_yq '.version // "local"' "$RUNNER_YML")

# Parse runtime into language and version
LANG=$(echo "$RUNTIME" | cut -d: -f1)
LANG_VERSION=$(echo "$RUNTIME" | cut -d: -f2)

echo "[RunSecure] Runtime: $LANG:$LANG_VERSION"
echo "[RunSecure] Tools: ${TOOLS:-none}"
echo "[RunSecure] RunSecure version: $RUNSECURE_VERSION"

# --- Determine image source (registry or local) -----------------------------
USE_REGISTRY=false
if [[ "$RUNSECURE_VERSION" != "local" && "$RUNSECURE_VERSION" != "null" ]]; then
    USE_REGISTRY=true
    REGISTRY_BASE="${REGISTRY_PREFIX}/base:${RUNSECURE_VERSION}"
    REGISTRY_LANG="${REGISTRY_PREFIX}/${LANG}:${RUNSECURE_VERSION}-${LANG_VERSION}"
    echo "[RunSecure] Registry mode: pulling from $REGISTRY_PREFIX"
fi

# --- Ensure base image exists ------------------------------------------------
if [[ "$USE_REGISTRY" == true ]]; then
    echo "[RunSecure] Pulling base: $REGISTRY_BASE"
    if docker pull "$REGISTRY_BASE" 2>/dev/null; then
        docker tag "$REGISTRY_BASE" "runner-base:latest"
    else
        echo "[RunSecure] WARNING: Pull failed for $REGISTRY_BASE. Falling back to local build."
        USE_REGISTRY=false
    fi
fi

if [[ "$USE_REGISTRY" == false ]]; then
    if ! docker image inspect "runner-base:latest" &>/dev/null; then
        echo "[RunSecure] Building runner-base..."
        docker build -f "${IMAGES_DIR}/base.Dockerfile" -t runner-base:latest "${RUNSECURE_ROOT}"
    fi
fi

# --- Ensure language image exists --------------------------------------------
LANG_IMAGE="runner-${LANG}:${LANG_VERSION}"
LANG_DOCKERFILE="${IMAGES_DIR}/${LANG}.Dockerfile"

if [[ "$USE_REGISTRY" == true ]]; then
    echo "[RunSecure] Pulling language image: $REGISTRY_LANG"
    if docker pull "$REGISTRY_LANG" 2>/dev/null; then
        docker tag "$REGISTRY_LANG" "$LANG_IMAGE"
    else
        echo "[RunSecure] WARNING: Pull failed for $REGISTRY_LANG. Falling back to local build."
        USE_REGISTRY=false
    fi
fi

if [[ "$USE_REGISTRY" == false ]] && ! docker image inspect "$LANG_IMAGE" &>/dev/null; then
    if [[ ! -f "$LANG_DOCKERFILE" ]]; then
        echo "[RunSecure] ERROR: No Dockerfile for language '$LANG' at $LANG_DOCKERFILE"
        exit 1
    fi

    echo "[RunSecure] Building $LANG_IMAGE..."

    case "$LANG" in
        node)   BUILD_ARG="NODE_VERSION=${LANG_VERSION}" ;;
        python) BUILD_ARG="PYTHON_VERSION=${LANG_VERSION}" ;;
        rust)   BUILD_ARG="RUST_VERSION=${LANG_VERSION}" ;;
        *)      BUILD_ARG="" ;;
    esac

    docker build \
        -f "$LANG_DOCKERFILE" \
        --build-arg "BASE_TAG=latest" \
        ${BUILD_ARG:+--build-arg "$BUILD_ARG"} \
        -t "$LANG_IMAGE" \
        "${RUNSECURE_ROOT}"
fi

# --- Generate project-specific Dockerfile ------------------------------------
# If no tools and no extra apt packages, use the language image directly.
if [[ -z "$TOOLS" && -z "$APT_PACKAGES" ]]; then
    echo "[RunSecure] No tools or extra packages — using $LANG_IMAGE directly."
    echo "$LANG_IMAGE"
    exit 0
fi

# Create a deterministic hash of the config to tag the image
# Include RunSecure version so different releases don't collide
CONFIG_HASH=$(echo "${RUNSECURE_VERSION}|${RUNTIME}|${TOOLS}|${APT_PACKAGES}" | sha256sum | cut -c1-12)
PROJECT_IMAGE="runner-project:${CONFIG_HASH}"

# Check if image already exists (skip rebuild unless --force)
if docker image inspect "$PROJECT_IMAGE" &>/dev/null && [[ "$FORCE_REBUILD" != "--force" ]]; then
    echo "[RunSecure] Image $PROJECT_IMAGE already exists (cached)."
    echo "$PROJECT_IMAGE"
    exit 0
fi

echo "[RunSecure] Composing project image: $PROJECT_IMAGE"

# Build a temporary Dockerfile
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

DOCKERFILE="${TMPDIR}/Dockerfile"

cat > "$DOCKERFILE" <<HEADER
# Auto-generated by RunSecure compose-image.sh
# Config hash: ${CONFIG_HASH}
FROM ${LANG_IMAGE}

USER root
HEADER

# Add extra apt packages if specified
if [[ -n "$APT_PACKAGES" ]]; then
    # H1: re-validate every apt name before writing it into the Dockerfile.
    # The schema validator already runs above (and rejects bad names), but
    # we re-check here as a defense-in-depth gate immediately adjacent to
    # the sink — any future code path that bypasses validate-schema.sh
    # must still pass through this guard.
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        if [[ ! "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; then
            echo "[RunSecure] ERROR: invalid apt package name '$pkg' rejected by H1 sink-side guard" >&2
            exit 1
        fi
    done <<< "$APT_PACKAGES"

    echo "" >> "$DOCKERFILE"
    echo "# --- Extra system packages from runner.yml ---" >> "$DOCKERFILE"
    # M8: apt-get update must succeed. Previously `2>/dev/null || true`
    # masked any update failure (network outage, stale repo signature,
    # disk-full etc.); apt-get install would then proceed with a stale
    # or empty index and pull whichever versions happened to be cached.
    echo "RUN apt-get update \\" >> "$DOCKERFILE"
    echo "    && apt-get install -y --no-install-recommends \\" >> "$DOCKERFILE"
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        echo "         ${pkg} \\" >> "$DOCKERFILE"
    done <<< "$APT_PACKAGES"
    echo "    && rm -rf /var/lib/apt/lists/*" >> "$DOCKERFILE"
fi

# Add tool recipes
if [[ -n "$TOOLS" ]]; then
    while IFS= read -r tool; do
        # Validate tool name: only alphanumeric, hyphens, underscores allowed
        if [[ ! "$tool" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "[RunSecure] ERROR: Invalid tool name '$tool' — only alphanumeric, hyphens, underscores allowed."
            exit 1
        fi
        RECIPE="${TOOLS_DIR}/${tool}.sh"
        if [[ ! -f "$RECIPE" ]]; then
            echo "[RunSecure] WARNING: No recipe for tool '$tool' at $RECIPE — skipping."
            continue
        fi
        echo "" >> "$DOCKERFILE"
        echo "# --- Tool: ${tool} (from tools/${tool}.sh) ---" >> "$DOCKERFILE"
        echo "COPY tools/${tool}.sh /tmp/install-${tool}.sh" >> "$DOCKERFILE"
        echo "RUN chmod +x /tmp/install-${tool}.sh && /tmp/install-${tool}.sh && rm /tmp/install-${tool}.sh" >> "$DOCKERFILE"
    done <<< "$TOOLS"
fi

# Finalize hardening (remove apt, re-strip setuid, lock /etc)
cat >> "$DOCKERFILE" <<FOOTER

# --- Finalize hardening (remove apt, strip setuid, lock /etc) ---
COPY infra/scripts/finalize-hardening.sh /tmp/finalize-hardening.sh
RUN chmod +x /tmp/finalize-hardening.sh && /tmp/finalize-hardening.sh && rm /tmp/finalize-hardening.sh

USER runner
WORKDIR /home/runner
FOOTER

echo "[RunSecure] Generated Dockerfile:"
cat "$DOCKERFILE"
echo ""

# Build the project image (using RunSecure root as context for tool scripts)
docker build \
    -f "$DOCKERFILE" \
    -t "$PROJECT_IMAGE" \
    "${RUNSECURE_ROOT}"

echo "[RunSecure] Built: $PROJECT_IMAGE"
echo "$PROJECT_IMAGE"
