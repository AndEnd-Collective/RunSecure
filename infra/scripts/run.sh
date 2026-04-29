#!/bin/bash
# ============================================================================
# RunSecure — Orchestrator
# ============================================================================
# Main entry point for running secure, containerized GitHub Actions runners.
#
# Reads a project's .github/runner.yml, builds/caches the appropriate image,
# generates the squid proxy config, requests a JIT token from GitHub, and
# launches an ephemeral runner container.
#
# Usage:
#   ./infra/scripts/run.sh --project /path/to/project --repo owner/repo
#   ./infra/scripts/run.sh --project /path/to/project --repo owner/repo --max-jobs 5
#
# Prerequisites:
#   - Docker
#   - gh CLI (authenticated)
#   - yq (brew install yq)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Auto-detect docker compose command
if docker compose version &>/dev/null; then
    DC="docker compose"
elif docker-compose version &>/dev/null; then
    DC="docker-compose"
else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' found."
    exit 1
fi

# --- Default arguments -------------------------------------------------------
PROJECT_DIR=""
REPO=""
MAX_JOBS=5
FORCE_REBUILD=false

# --- Parse arguments ---------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)    PROJECT_DIR="$2"; shift 2 ;;
        --repo)       REPO="$2"; shift 2 ;;
        --max-jobs)   MAX_JOBS="$2"; shift 2 ;;
        --force)      FORCE_REBUILD=true; shift ;;
        -h|--help)
            echo "Usage: run.sh --project /path/to/project --repo owner/repo [options]"
            echo ""
            echo "Options:"
            echo "  --project PATH    Path to the project directory (must contain .github/runner.yml)"
            echo "  --repo OWNER/REPO GitHub repository (e.g., NaorPenso/datacentric)"
            echo "  --max-jobs N      Maximum jobs to process (default: 5)"
            echo "  --force           Force rebuild of project image"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# --- Validate arguments ------------------------------------------------------
if [[ -z "$PROJECT_DIR" ]]; then
    echo "[RunSecure] ERROR: --project is required."
    exit 1
fi

if [[ -z "$REPO" ]]; then
    echo "[RunSecure] ERROR: --repo is required."
    exit 1
fi

RUNNER_YML="${PROJECT_DIR}/.github/runner.yml"

# --- Pull latest project config ----------------------------------------------
if [[ -d "${PROJECT_DIR}/.git" ]]; then
    echo "[RunSecure] Pulling latest project config..."
    git -C "$PROJECT_DIR" pull --ff-only --quiet 2>/dev/null || {
        echo "[RunSecure] WARNING: git pull failed (offline or uncommitted changes). Using local config."
    }
fi

if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[RunSecure] ERROR: No .github/runner.yml found in $PROJECT_DIR"
    exit 1
fi

# --- Read config from runner.yml ---------------------------------------------
MEMORY=$(yq '.resources.memory // "8g"' "$RUNNER_YML")
CPUS=$(yq '.resources.cpus // "4"' "$RUNNER_YML")
PIDS=$(yq '.resources.pids // "2048"' "$RUNNER_YML")
LABELS=$(yq '.labels // ["self-hosted", "Linux", "ARM64", "container"] | join(",")' "$RUNNER_YML")
RUNSECURE_VERSION=$(yq '.version // "local"' "$RUNNER_YML")

# --- Derive a human-readable container name prefix from repo -----------------
# "owner/my-repo" → "rs-my-repo"
REPO_SHORT=$(echo "$REPO" | sed 's|.*/||; s/[^a-zA-Z0-9_-]/-/g' | tr '[:upper:]' '[:lower:]')
CONTAINER_PREFIX="rs-${REPO_SHORT}"

# --- Build/cache the project image ------------------------------------------
echo "=== RunSecure Orchestrator ==="
echo "Project: $PROJECT_DIR"
echo "Repo:    $REPO"
echo "Version: $RUNSECURE_VERSION"
echo "Labels:  $LABELS"
echo ""

COMPOSE_ARGS=""
if [[ "$FORCE_REBUILD" == true ]]; then
    COMPOSE_ARGS="--force"
fi

# compose-image.sh outputs the final image name as its last line
IMAGE_NAME=$("${SCRIPT_DIR}/compose-image.sh" "$PROJECT_DIR" $COMPOSE_ARGS | tail -1)
echo ""
echo "[RunSecure] Using image: $IMAGE_NAME"

# --- Resolve proxy image (registry or local) ---------------------------------
REGISTRY_PREFIX="ghcr.io/andend-collective/runsecure"
if [[ "$RUNSECURE_VERSION" != "local" && "$RUNSECURE_VERSION" != "null" ]]; then
    PROXY_IMAGE="${REGISTRY_PREFIX}/proxy:${RUNSECURE_VERSION}"
    echo "[RunSecure] Using proxy: $PROXY_IMAGE"
    if ! docker pull "$PROXY_IMAGE" 2>/dev/null; then
        echo "[RunSecure] ERROR: Could not pull proxy image: $PROXY_IMAGE"
        echo "[RunSecure] Verify the version exists at $REGISTRY_PREFIX or use version: local"
        exit 1
    fi
else
    # Local mode: build proxy from source if not cached
    PROXY_IMAGE="runsecure-proxy:latest"
    if ! docker image inspect "$PROXY_IMAGE" &>/dev/null; then
        echo "[RunSecure] Building proxy image..."
        docker build -f "${RUNSECURE_ROOT}/infra/squid/Dockerfile" \
            -t "$PROXY_IMAGE" "${RUNSECURE_ROOT}/infra/squid"
    fi
fi
export PROXY_IMAGE

# --- Generate egress config (squid + haproxy + dnsmasq + compose overlay) ----
"${SCRIPT_DIR}/generate-egress-conf.sh" "$PROJECT_DIR"

# --- Job loop ----------------------------------------------------------------
echo ""
echo "[RunSecure] Ready to process up to $MAX_JOBS jobs. Press Ctrl+C to stop."
echo ""

cleanup() {
    echo ""
    echo "[RunSecure] Shutting down..."
    local _cleanup_compose="${RUNSECURE_ROOT}/infra/runtime-compose.yml"
    if [[ -f "$_cleanup_compose" ]]; then
        $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" -f "$_cleanup_compose" down --remove-orphans 2>/dev/null || true
    else
        $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" down --remove-orphans 2>/dev/null || true
    fi
}
trap cleanup EXIT

for i in $(seq 1 "$MAX_JOBS"); do
    echo "--- Job $i/$MAX_JOBS: Requesting JIT token ---"

    # Request a Just-In-Time runner configuration from GitHub
    JIT_RESPONSE=$(gh api -X POST "repos/$REPO/actions/runners/generate-jitconfig" \
        --input - <<EOF
{
    "name": "${CONTAINER_PREFIX}-job${i}-$(date +%s)",
    "runner_group_id": 1,
    "labels": [$(echo "$LABELS" | sed 's/,/","/g;s/^/"/;s/$/"/')],
    "work_folder": "_work"
}
EOF
    ) || {
        echo "[RunSecure] No pending jobs or failed to get JIT token. Waiting 10s..."
        sleep 10
        continue
    }

    JIT_CONFIG=$(echo "$JIT_RESPONSE" | jq -r '.encoded_jit_config // empty')

    if [[ -z "$JIT_CONFIG" ]]; then
        echo "[RunSecure] No JIT config received. Trying registration token fallback..."

        # Fallback: use registration token (less secure but more compatible)
        REG_TOKEN=$(gh api -X POST "repos/$REPO/actions/runners/registration-token" --jq '.token')
        if [[ -z "$REG_TOKEN" ]]; then
            echo "[RunSecure] ERROR: Could not get registration token."
            break
        fi

        # For registration token mode, we pass it differently
        echo "[RunSecure] WARNING: Using registration token (less secure than JIT)."
        echo "[RunSecure] Registration token mode not yet implemented — use run-legacy.sh."
        break
    fi

    echo "[RunSecure] JIT token acquired. Launching container..."

    # --- Source diag rotation helper ---
    RUN_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    RUN_SH_REPO_ROOT="$RUNSECURE_ROOT"
    # SC1091: path is dynamic; pass -x to shellcheck for full analysis.
    # shellcheck disable=SC1091
    source "$RUN_SH_DIR/lib/diag-rotation.sh"

    # --- Rotate diag directories ---
    rotate_diag_dirs "$RUN_SH_REPO_ROOT"

    # runtime-compose.yml was already generated by generate-egress-conf.sh above
    RUNTIME_COMPOSE="$RUN_SH_REPO_ROOT/infra/runtime-compose.yml"

    # Launch runner + proxy via docker compose
    RUNNER_IMAGE="$IMAGE_NAME" \
    RUNNER_JIT_CONFIG="$JIT_CONFIG" \
    RUNNER_NAME="${CONTAINER_PREFIX}-job${i}" \
    RUNNER_MEMORY="$MEMORY" \
    RUNNER_CPUS="$CPUS" \
    RUNNER_PIDS="$PIDS" \
    $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" -f "$RUNTIME_COMPOSE" \
        up --abort-on-container-exit --exit-code-from runner

    # Clean up for next iteration
    $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" -f "$RUNTIME_COMPOSE" down --remove-orphans 2>/dev/null || true

    echo ""
    echo "--- Job $i/$MAX_JOBS: Complete ---"
    echo ""
done

echo "=== RunSecure: All jobs processed ==="
