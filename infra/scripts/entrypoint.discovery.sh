#!/bin/bash
# ============================================================================
# RunSecure — Log-Upload Marker Discovery Entrypoint
# ============================================================================
# Wraps the GitHub Actions runner. After Runner.Listener exits, dumps the tail
# of the most recent _diag/Worker_*.log and sleeps 60s so the container can
# be inspected before teardown.
#
# THIS IS NOT FOR PRODUCTION USE. PR3 replaces this with a proper
# foreground+wait entrypoint based on the marker discovered here.
# ============================================================================

set -euo pipefail

RUNNER_DIR="/home/runner/actions-runner"

if [[ -z "${RUNNER_JIT_CONFIG:-}" ]]; then
    echo "[RunSecure-discovery] ERROR: RUNNER_JIT_CONFIG is not set."
    exit 1
fi

if [[ -n "${HTTP_PROXY:-}" ]]; then
    echo "[RunSecure-discovery] Proxy: ${HTTP_PROXY}"
    export http_proxy="${HTTP_PROXY}"
    export https_proxy="${HTTPS_PROXY:-$HTTP_PROXY}"
    export no_proxy="localhost,127.0.0.1"
fi

JIT_CONFIG="${RUNNER_JIT_CONFIG}"
unset RUNNER_JIT_CONFIG

cd "${RUNNER_DIR}"

echo "[RunSecure-discovery] Starting actions-runner..."
./run.sh --jitconfig "${JIT_CONFIG}" &
RUNNER_PID=$!
set +e
wait "${RUNNER_PID}"
RUNNER_EXIT_CODE=$?
set -e

echo "[RunSecure-discovery] === RUNNER EXITED (code: ${RUNNER_EXIT_CODE}) ==="

WORKER_LOG="$(find "${RUNNER_DIR}/_diag" -maxdepth 1 -name 'Worker_*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n 1 | cut -d' ' -f2- || true)"
if [[ -n "${WORKER_LOG}" ]]; then
    echo "[RunSecure-discovery] === BEGIN: tail -n 200 ${WORKER_LOG} ==="
    tail -n 200 "${WORKER_LOG}"
    echo "[RunSecure-discovery] === END ==="
else
    echo "[RunSecure-discovery] WARNING: no Worker_*.log found in _diag/"
fi

LISTENER_LOG="$(find "${RUNNER_DIR}/_diag" -maxdepth 1 -name 'Runner_*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n 1 | cut -d' ' -f2- || true)"
if [[ -n "${LISTENER_LOG}" ]]; then
    echo "[RunSecure-discovery] === BEGIN: tail -n 50 ${LISTENER_LOG} ==="
    tail -n 50 "${LISTENER_LOG}"
    echo "[RunSecure-discovery] === END ==="
fi

echo "[RunSecure-discovery] Sleeping 60s — inspect the container now if needed."
sleep 60

echo "[RunSecure-discovery] Exit code: ${RUNNER_EXIT_CODE}"
exit "${RUNNER_EXIT_CODE}"
