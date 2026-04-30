#!/bin/bash
# ============================================================================
# RunSecure — Container Entrypoint
# ============================================================================
# Starts the GitHub Actions runner with JIT configuration.
#
# After the runner exits, this entrypoint waits for the runner's log
# upload to complete (so the GitHub UI shows actual stderr instead of
# BlobNotFound) and then exits with the runner's exit code.
#
# The wait is bounded by RUNSECURE_LOG_UPLOAD_TIMEOUT (default 30s).
# The marker we wait for is in RUNSECURE_LOG_UPLOAD_MARKER. Both are
# overridable via the orchestrator environment.
#
# If the wait times out, the host-mounted _diag/ volume preserves the
# logs for operator-side recovery. See infra/scripts/run.sh.
#
# Expected environment:
#   RUNNER_JIT_CONFIG               — Base64-encoded JIT config
#   RUNNER_NAME                     — (optional) Override runner name
#   HTTP_PROXY / HTTPS_PROXY        — (optional) Squid proxy address
#   RUNSECURE_LOG_UPLOAD_MARKER     — Substring to wait for in Worker_*.log
#   RUNSECURE_LOG_UPLOAD_TIMEOUT    — Max seconds to wait (default 30)
# ============================================================================

set -euo pipefail

RUNNER_DIR="/home/runner/actions-runner"

# --- Validate environment ---
if [[ -z "${RUNNER_JIT_CONFIG:-}" ]]; then
    echo "[RunSecure] ERROR: RUNNER_JIT_CONFIG is not set."
    echo "[RunSecure] The orchestrator must pass a JIT config from the GitHub API."
    exit 1
fi

# --- Configure proxy if set ---
if [[ -n "${HTTP_PROXY:-}" ]]; then
    echo "[RunSecure] Proxy configured: ${HTTP_PROXY}"
    export http_proxy="${HTTP_PROXY}"
    export https_proxy="${HTTPS_PROXY:-$HTTP_PROXY}"
    export no_proxy="localhost,127.0.0.1"
fi

# --- Clear sensitive env vars after reading them ---
JIT_CONFIG="${RUNNER_JIT_CONFIG}"
unset RUNNER_JIT_CONFIG

# --- Default values for log-upload wait ---
LOG_UPLOAD_TIMEOUT="${RUNSECURE_LOG_UPLOAD_TIMEOUT:-30}"
# Default marker is the final unconditional Trace.Info() emitted by
# JobServerQueue.ShutdownAsync() after all upload queues drain. Source-
# verified in PR2; see tests/discovery/findings.md.
LOG_UPLOAD_MARKER="${RUNSECURE_LOG_UPLOAD_MARKER:-All queue process tasks have been stopped, and all queues are drained.}"

# --- Start the runner as a foreground child ---
echo "[RunSecure] Starting ephemeral runner..."
echo "[RunSecure] User: $(whoami) (UID: $(id -u))"
echo "[RunSecure] Workspace: ${RUNNER_DIR}/_work"

cd "${RUNNER_DIR}"

./run.sh --jitconfig "${JIT_CONFIG}" &
RUNNER_PID=$!

# wait can return non-zero (e.g. exit 1 from the runner). Disable -e
# around wait, capture exit code, re-enable.
set +e
wait "${RUNNER_PID}"
RUNNER_EXIT_CODE=$?
set -e

echo "[RunSecure] Runner exited (code: ${RUNNER_EXIT_CODE}). Waiting for log upload (timeout: ${LOG_UPLOAD_TIMEOUT}s)..."

# --- Wait for the upload-complete marker ---
WORKER_LOG="$(find "${RUNNER_DIR}/_diag" -maxdepth 1 -name 'Worker_*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n 1 | cut -d' ' -f2- || true)"
DEADLINE=$(( $(date +%s) + LOG_UPLOAD_TIMEOUT ))

if [[ -z "${WORKER_LOG}" ]]; then
    echo "[RunSecure] WARNING: no Worker_*.log found in _diag/. Skipping wait."
elif grep -q "${LOG_UPLOAD_MARKER}" "${WORKER_LOG}" 2>/dev/null; then
    echo "[RunSecure] Log upload already confirmed in worker log."
else
    while (( $(date +%s) < DEADLINE )); do
        if grep -q "${LOG_UPLOAD_MARKER}" "${WORKER_LOG}" 2>/dev/null; then
            echo "[RunSecure] Log upload confirmed."
            break
        fi
        sleep 1
    done
    if (( $(date +%s) >= DEADLINE )); then
        echo "[RunSecure] WARNING: log upload wait timed out after ${LOG_UPLOAD_TIMEOUT}s."
        echo "[RunSecure] _diag/ is host-mounted; logs are recoverable from the host."
    fi
fi

exit "${RUNNER_EXIT_CODE}"
