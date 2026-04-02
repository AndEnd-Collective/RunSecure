#!/bin/bash
# ============================================================================
# RunSecure Tool Recipe — Cypress
# ============================================================================
# Installs Cypress and its system dependencies for headless browser testing.
#
# Requirements: Node.js must be installed (node.Dockerfile layer).
# Image size impact: ~250 MB
# ============================================================================

set -euo pipefail

# Cypress system dependencies
apt-get update
apt-get install -y --no-install-recommends \
    libgtk2.0-0 \
    libgtk-3-0 \
    libgbm-dev \
    libnotify-dev \
    libnss3 \
    libxss1 \
    libasound2 \
    libxtst6 \
    xauth \
    xvfb
rm -rf /var/lib/apt/lists/*

# Install Cypress globally so it's cached in the image
npm install -g cypress

# Verify the binary works
HOME=/home/runner cypress verify

echo "[RunSecure] Cypress installed successfully."
