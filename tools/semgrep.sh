#!/bin/bash
# ============================================================================
# RunSecure Tool Recipe — Semgrep
# ============================================================================
# Installs Semgrep static analysis tool via pip.
#
# Requirements: Python 3 must be available (installed as a dependency).
# Image size impact: ~276 MB
# ============================================================================

set -euo pipefail

# Semgrep requires Python 3. If not already installed (e.g., on a Node
# runner), install a minimal Python.
if ! command -v python3 &>/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends python3 python3-pip
    rm -rf /var/lib/apt/lists/*
fi

# Install semgrep via pip (system-wide so the runner user can use it)
pip3 install --no-cache-dir --break-system-packages semgrep

# Verify
semgrep --version

echo "[RunSecure] Semgrep installed successfully."
