#!/bin/bash
# ============================================================================
# RunSecure Tool Recipe — Semgrep
# ============================================================================
# Installs Semgrep static analysis tool via pip.
#
# Requirements: Python 3 is auto-installed if not present.
# Image size impact: ~276 MB
# ============================================================================

set -euo pipefail

# Semgrep requires Python 3. If not already installed (e.g., on a Node
# runner), install a minimal Python.
if ! command -v python3 &>/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv
    rm -rf /var/lib/apt/lists/*
fi

# Ensure pip is available (Debian bookworm may need ensurepip)
if ! python3 -m pip --version &>/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends python3-pip
    rm -rf /var/lib/apt/lists/*
fi

# Install semgrep via pip
python3 -m pip install --no-cache-dir --break-system-packages semgrep

# Verify
semgrep --version

echo "[RunSecure] Semgrep installed successfully."
