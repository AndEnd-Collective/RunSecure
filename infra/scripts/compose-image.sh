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
# If runner.yml specifies a `version:` field, an exact release terminal image
# is pulled from GHCR when no additions are requested. Project additions start
# from that release's separately published build-only language stage, then
# apply final hardening. Versioned pulls fail closed instead of silently mixing
# a released base with mutable language/tool inputs from the local checkout.
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

# H2: hardening.remove + hardening.stub — comma-separated lists baked
# into the image as env vars consumed by finalize-hardening.sh. The
# schema validator already rejected anything that isn't a clean tool
# name, but we redo the regex check here as a sink-side guard.
HARDENING_REMOVE=$(_yq '(.hardening.remove // []) | join(",")' "$RUNNER_YML")
HARDENING_STUB=$(_yq '(.hardening.stub // []) | join(",")' "$RUNNER_YML")
[[ "$HARDENING_REMOVE" == "null" ]] && HARDENING_REMOVE=""
[[ "$HARDENING_STUB"   == "null" ]] && HARDENING_STUB=""
for _name in ${HARDENING_REMOVE//,/ } ${HARDENING_STUB//,/ }; do
    [[ -z "$_name" ]] && continue
    if [[ ! "$_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[RunSecure] ERROR: invalid hardening tool name '$_name' rejected by H2 sink-side guard" >&2
        exit 1
    fi
done

# Published language images are terminal: apt/dpkg are gone and /etc is
# locked. Any project-requested package, tool, or H2 override must therefore
# start from the language Dockerfile's build-only *-build stage and run the
# finalizer only after those additions have been applied.
NEEDS_COMPOSITION=false
if [[ -n "$TOOLS" || -n "$APT_PACKAGES" || -n "$HARDENING_REMOVE" || -n "$HARDENING_STUB" ]]; then
    NEEDS_COMPOSITION=true
fi

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
    REGISTRY_LANG="${REGISTRY_PREFIX}/${LANG}:${RUNSECURE_VERSION}-${LANG_VERSION}"
    echo "[RunSecure] Registry mode: pulling from $REGISTRY_PREFIX"
fi

# --- Ensure base image exists ------------------------------------------------
if [[ "$USE_REGISTRY" == false ]]; then
    if ! docker image inspect "runner-base:latest" &>/dev/null; then
        echo "[RunSecure] Building runner-base..."
        docker build -f "${IMAGES_DIR}/base.Dockerfile" -t runner-base:latest "${RUNSECURE_ROOT}"
    fi
fi

# --- Ensure language image/build stage exists --------------------------------
LANG_IMAGE="runner-${LANG}:${LANG_VERSION}"
LANG_DOCKERFILE="${IMAGES_DIR}/${LANG}.Dockerfile"
BUILD_SOURCE_VERSION="$RUNSECURE_VERSION"
[[ "$BUILD_SOURCE_VERSION" == "null" ]] && BUILD_SOURCE_VERSION="local"
BUILD_SOURCE_ID="$BUILD_SOURCE_VERSION"

if [[ ! -f "$LANG_DOCKERFILE" ]]; then
    echo "[RunSecure] ERROR: No Dockerfile for language '$LANG' at $LANG_DOCKERFILE"
    exit 1
fi

if [[ "$USE_REGISTRY" == false ]]; then
    BASE_IMAGE_ID=$(docker image inspect --format '{{.Id}}' runner-base:latest)
    BUILD_SOURCE_ID=$(
        {
            printf '%s\n' "$BASE_IMAGE_ID"
            sha256sum "$LANG_DOCKERFILE" \
                "${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh" \
                "${TOOLS_DIR}"/*.sh
        } | sha256sum | cut -d' ' -f1
    )
    BUILD_SOURCE_VERSION="local-${BUILD_SOURCE_ID:0:12}"
fi
LANG_BUILD_IMAGE="runner-${LANG}-build:${BUILD_SOURCE_VERSION}-${LANG_VERSION}"

# Registry language packages are immutable release inputs. The terminal image
# carries the exact composition-stage digest that produced it. Never fall back
# to local Dockerfiles for a versioned request: doing so would produce a hybrid
# image under a release key.
if [[ "$USE_REGISTRY" == true ]]; then
    echo "[RunSecure] Pulling release image: $REGISTRY_LANG"
    if ! docker pull "$REGISTRY_LANG"; then
        echo "[RunSecure] ERROR: Required release image unavailable: $REGISTRY_LANG" >&2
        exit 1
    fi
    docker tag "$REGISTRY_LANG" "$LANG_IMAGE"
    BUILD_SOURCE_ID=$(docker image inspect \
        --format '{{join .RepoDigests ","}}' "$REGISTRY_LANG")
    if [[ -z "$BUILD_SOURCE_ID" ]]; then
        echo "[RunSecure] ERROR: Pulled release image has no immutable RepoDigest: $REGISTRY_LANG" >&2
        exit 1
    fi

    if [[ "$NEEDS_COMPOSITION" == true ]]; then
        COMPOSITION_BASE=$(docker image inspect \
            --format '{{index .Config.Labels "io.runsecure.composition-base"}}' \
            "$REGISTRY_LANG")
        expected_builder="${REGISTRY_PREFIX}/${LANG}-build"
        builder_digest="${COMPOSITION_BASE#*@}"
        if [[ "${COMPOSITION_BASE%@*}" != "$expected_builder" \
            || ! "$builder_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
            echo "[RunSecure] ERROR: $REGISTRY_LANG lacks a valid $LANG composition digest" >&2
            exit 1
        fi
        echo "[RunSecure] Pulling immutable composition stage: $COMPOSITION_BASE"
        if ! docker pull "$COMPOSITION_BASE"; then
            echo "[RunSecure] ERROR: Required composition stage unavailable: $COMPOSITION_BASE" >&2
            exit 1
        fi
        docker tag "$COMPOSITION_BASE" "$LANG_BUILD_IMAGE"
        BUILD_SOURCE_ID="$COMPOSITION_BASE"
    fi
fi

IMAGE_TO_BUILD="$LANG_IMAGE"
BUILD_TARGET_ARGS=()
if [[ "$NEEDS_COMPOSITION" == true ]]; then
    IMAGE_TO_BUILD="$LANG_BUILD_IMAGE"
    BUILD_TARGET_ARGS=(--target "${LANG}-build")
fi

if [[ "$USE_REGISTRY" == false ]] \
    && { [[ "$FORCE_REBUILD" == "--force" ]] || ! docker image inspect "$IMAGE_TO_BUILD" &>/dev/null; }; then
    echo "[RunSecure] Building $IMAGE_TO_BUILD..."

    case "$LANG" in
        node)   BUILD_ARG="NODE_VERSION=${LANG_VERSION}" ;;
        python) BUILD_ARG="PYTHON_VERSION=${LANG_VERSION}" ;;
        rust)   BUILD_ARG="RUST_VERSION=${LANG_VERSION}" ;;
        *)      BUILD_ARG="" ;;
    esac

    docker build \
        -f "$LANG_DOCKERFILE" \
        "${BUILD_TARGET_ARGS[@]}" \
        --build-arg "BASE_REF=runner-base:latest" \
        ${BUILD_ARG:+--build-arg "$BUILD_ARG"} \
        -t "$IMAGE_TO_BUILD" \
        "${RUNSECURE_ROOT}"
fi

# --- Generate project-specific Dockerfile ------------------------------------
# If there are no additions, use the terminal language image directly.
if [[ "$NEEDS_COMPOSITION" == false ]]; then
    echo "[RunSecure] No tools or extra packages or hardening overrides — using $LANG_IMAGE directly."
    echo "$LANG_IMAGE"
    exit 0
fi

# Create a deterministic hash of the config to tag the image
# Include RunSecure version so different releases don't collide
CONFIG_HASH=$(echo "${RUNSECURE_VERSION}|${BUILD_SOURCE_ID}|${RUNTIME}|${TOOLS}|${APT_PACKAGES}|${HARDENING_REMOVE}|${HARDENING_STUB}" | sha256sum | cut -c1-12)
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
FROM ${LANG_BUILD_IMAGE}

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
        if [[ "$USE_REGISTRY" == false && ! -f "$RECIPE" ]]; then
            echo "[RunSecure] WARNING: No recipe for tool '$tool' at $RECIPE — skipping."
            continue
        fi
        echo "" >> "$DOCKERFILE"
        echo "# --- Tool: ${tool} (embedded in the release composition stage) ---" >> "$DOCKERFILE"
        echo "RUN test -f /opt/runsecure/composition/tools/${tool}.sh \\" >> "$DOCKERFILE"
        echo "    && /opt/runsecure/composition/tools/${tool}.sh" >> "$DOCKERFILE"
    done <<< "$TOOLS"
fi

# Finalize hardening (remove apt, re-strip setuid, lock /etc, H2 prune)
cat >> "$DOCKERFILE" <<FOOTER

# --- Finalize hardening (remove apt, strip setuid, lock /etc) ---
# H2: pass the user's hardening.remove / hardening.stub lists as build
# args. finalize-hardening.sh reads these from the environment.
ARG RUNSECURE_HARDENING_REMOVE=""
ARG RUNSECURE_HARDENING_STUB=""
ENV RUNSECURE_HARDENING_REMOVE=\${RUNSECURE_HARDENING_REMOVE}
ENV RUNSECURE_HARDENING_STUB=\${RUNSECURE_HARDENING_STUB}
RUN /opt/runsecure/composition/finalize-hardening.sh \
    && rm -rf /opt/runsecure/composition
# Don't carry the build-time vars into the runtime image — they're
# consumed during finalize-hardening only.
ENV RUNSECURE_HARDENING_REMOVE=""
ENV RUNSECURE_HARDENING_STUB=""

USER runner
WORKDIR /home/runner
FOOTER

echo "[RunSecure] Generated Dockerfile:"
cat "$DOCKERFILE"
echo ""

# Build the project image (using RunSecure root as context for tool scripts)
docker build \
    -f "$DOCKERFILE" \
    --build-arg "RUNSECURE_HARDENING_REMOVE=${HARDENING_REMOVE}" \
    --build-arg "RUNSECURE_HARDENING_STUB=${HARDENING_STUB}" \
    -t "$PROJECT_IMAGE" \
    "${RUNSECURE_ROOT}"

echo "[RunSecure] Built: $PROJECT_IMAGE"
echo "$PROJECT_IMAGE"
