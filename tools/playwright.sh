#!/bin/bash
# ============================================================================
# RunSecure Tool Recipe — Playwright + Chromium
# ============================================================================
# Installs Playwright and bakes Chromium into the image so it is not
# downloaded at runtime (faster CI, smaller egress allowlist).
#
# Requirements: Node.js must be installed (node.Dockerfile layer).
# Image size impact: ~300 MB (Chromium browser binary + system deps)
# ============================================================================

set -euo pipefail

# Playwright needs system libraries for Chromium (X11, fonts, etc.)
# These are installed via npx playwright install-deps which calls apt.
apt-get update
apt-get install -y --no-install-recommends \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libx11-xcb1 \
    fonts-liberation \
    xdg-utils
rm -rf /var/lib/apt/lists/*

# Install Playwright CLI and download Chromium only (not Firefox/WebKit)
# Note: su is removed by base hardening, so use HOME override to install
# as root but to the runner user's cache location.
HOME=/home/runner npx --yes playwright install chromium

# Fix ownership: npx ran as root, so .cache and .npm are root-owned.
# The runner user (1001) needs to write to these at runtime.
chown -R runner:0 /home/runner/.cache 2>/dev/null || true
chown -R runner:0 /home/runner/.npm 2>/dev/null || true

echo "[RunSecure] Playwright + Chromium installed successfully."
