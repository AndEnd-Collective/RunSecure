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
su -s /bin/bash runner -c "npx --yes playwright install chromium"

echo "[RunSecure] Playwright + Chromium installed successfully."
