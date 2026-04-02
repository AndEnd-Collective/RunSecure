#!/bin/bash
# ============================================================================
# RunSecure — Container Entrypoint
# ============================================================================
# Starts the GitHub Actions runner with JIT configuration.
# The JIT config is a single-use, time-limited token passed as an environment
# variable by the orchestrator. No long-lived credentials are stored.
#
# Expected environment:
#   RUNNER_JIT_CONFIG  — Base64-encoded JIT configuration from GitHub API
#   RUNNER_NAME        — (optional) Override runner name
#   HTTP_PROXY         — (optional) Squid proxy address
#   HTTPS_PROXY        — (optional) Squid proxy address
# ============================================================================

set -euo pipefail

RUNNER_DIR="/home/runner/actions-runner"

# --- Validate environment ----------------------------------------------------
if [[ -z "${RUNNER_JIT_CONFIG:-}" ]]; then
    echo "[RunSecure] ERROR: RUNNER_JIT_CONFIG is not set."
    echo "[RunSecure] The orchestrator must pass a JIT config from the GitHub API."
    exit 1
fi

# --- Configure proxy if set --------------------------------------------------
if [[ -n "${HTTP_PROXY:-}" ]]; then
    echo "[RunSecure] Proxy configured: ${HTTP_PROXY}"
    export http_proxy="${HTTP_PROXY}"
    export https_proxy="${HTTPS_PROXY:-$HTTP_PROXY}"
    export no_proxy="localhost,127.0.0.1"
fi

# --- Clear sensitive env vars after reading them -----------------------------
# Store the JIT config then unset it so workflow steps can't read it.
JIT_CONFIG="${RUNNER_JIT_CONFIG}"
unset RUNNER_JIT_CONFIG

# --- Start the runner --------------------------------------------------------
echo "[RunSecure] Starting ephemeral runner..."
echo "[RunSecure] Runner version: $(cat "${RUNNER_DIR}/bin/Runner.Listener.deps.json" 2>/dev/null | jq -r '.libraries | keys[] | select(startswith("Microsoft.VisualStudio.Services.Agent"))' 2>/dev/null || echo 'unknown')"
echo "[RunSecure] User: $(whoami) (UID: $(id -u))"
echo "[RunSecure] Workspace: ${RUNNER_DIR}/_work"

cd "${RUNNER_DIR}"

# JIT config mode: runner auto-configures and runs a single job, then exits.
exec ./run.sh --jitconfig "${JIT_CONFIG}"
