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
#   ./infra/scripts/run.sh --project /path/to/project --repo owner/repo --no-proxy
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
USE_PROXY=true
FORCE_REBUILD=false

# --- Parse arguments ---------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)    PROJECT_DIR="$2"; shift 2 ;;
        --repo)       REPO="$2"; shift 2 ;;
        --max-jobs)   MAX_JOBS="$2"; shift 2 ;;
        --no-proxy)   USE_PROXY=false; shift ;;
        --force)      FORCE_REBUILD=true; shift ;;
        -h|--help)
            echo "Usage: run.sh --project /path/to/project --repo owner/repo [options]"
            echo ""
            echo "Options:"
            echo "  --project PATH    Path to the project directory (must contain .github/runner.yml)"
            echo "  --repo OWNER/REPO GitHub repository (e.g., NaorPenso/datacentric)"
            echo "  --max-jobs N      Maximum jobs to process (default: 5)"
            echo "  --no-proxy        Skip egress proxy (less secure, useful for debugging)"
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
if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[RunSecure] ERROR: No .github/runner.yml found in $PROJECT_DIR"
    exit 1
fi

# --- Read resource limits from runner.yml ------------------------------------
MEMORY=$(yq '.resources.memory // "6g"' "$RUNNER_YML")
CPUS=$(yq '.resources.cpus // "4"' "$RUNNER_YML")
PIDS=$(yq '.resources.pids // "1024"' "$RUNNER_YML")
LABELS=$(yq '.labels // ["self-hosted", "Linux", "ARM64", "container"] | join(",")' "$RUNNER_YML")

# --- Build/cache the project image ------------------------------------------
echo "=== RunSecure Orchestrator ==="
echo "Project: $PROJECT_DIR"
echo "Repo:    $REPO"
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

# --- Generate squid proxy config ---------------------------------------------
if [[ "$USE_PROXY" == true ]]; then
    "${SCRIPT_DIR}/generate-squid-conf.sh" "$PROJECT_DIR"
fi

# --- Job loop ----------------------------------------------------------------
echo ""
echo "[RunSecure] Ready to process up to $MAX_JOBS jobs. Press Ctrl+C to stop."
echo ""

cleanup() {
    echo ""
    echo "[RunSecure] Shutting down..."
    $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 "$MAX_JOBS"); do
    echo "--- Job $i/$MAX_JOBS: Requesting JIT token ---"

    # Request a Just-In-Time runner configuration from GitHub
    JIT_RESPONSE=$(gh api -X POST "repos/$REPO/actions/runners/generate-jitconfig" \
        --input - <<EOF
{
    "name": "runsecure-$(date +%s)",
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

    # Launch runner via docker compose
    if [[ "$USE_PROXY" == true ]]; then
        RUNNER_IMAGE="$IMAGE_NAME" \
        RUNNER_JIT_CONFIG="$JIT_CONFIG" \
        RUNNER_NAME="runsecure-$(date +%s)" \
        RUNNER_MEMORY="$MEMORY" \
        RUNNER_CPUS="$CPUS" \
        RUNNER_PIDS="$PIDS" \
        $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" \
            up --abort-on-container-exit --exit-code-from runner

        # Clean up for next iteration
        $DC -f "${RUNSECURE_ROOT}/infra/docker-compose.yml" down --remove-orphans 2>/dev/null || true
    else
        # Direct mode (no proxy) — use docker run with hardening flags
        docker run \
            --rm \
            --name "runsecure-runner-$(date +%s)" \
            --user 1001:0 \
            --security-opt=no-new-privileges \
            --security-opt="seccomp=${RUNSECURE_ROOT}/infra/seccomp/node-runner.json" \
            --cap-drop=ALL \
            --tmpfs "/tmp:rw,noexec,nosuid,size=2g" \
            --memory="$MEMORY" \
            --memory-swap="$MEMORY" \
            --cpus="$CPUS" \
            --pids-limit="$PIDS" \
            --ulimit nofile=4096:4096 \
            --ulimit nproc=2048:2048 \
            -e "RUNNER_JIT_CONFIG=${JIT_CONFIG}" \
            -e "RUNNER_NAME=runsecure-$(date +%s)" \
            -e "SEMGREP_SETTINGS_FILE=/home/runner/.semgrep/settings.yml" \
            -e "SEMGREP_VERSION_CACHE_PATH=/home/runner/.semgrep/versions" \
            -v "${RUNSECURE_ROOT}/infra/scripts/entrypoint.sh:/home/runner/entrypoint.sh:ro" \
            --entrypoint "/home/runner/entrypoint.sh" \
            "$IMAGE_NAME"
    fi

    echo ""
    echo "--- Job $i/$MAX_JOBS: Complete ---"
    echo ""
done

echo "=== RunSecure: All jobs processed ==="
