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

# H9: pin Playwright version. `npx --yes playwright` would resolve to
# whatever the latest version is at image-build time. Renovate updates
# the constant.
# renovate: datasource=npm depName=playwright
# 1.59.1 (2026-04-01) — latest stable, comfortably past the 48h gate.
PLAYWRIGHT_VERSION="1.59.1"

# Install Playwright globally with pinned version, then use the pinned
# binary to download Chromium. We install via npm rather than running
# `npx --yes playwright@VERSION` so the resolved package is on PATH for
# downstream workflows that call `playwright` directly.
npm install -g "playwright@${PLAYWRIGHT_VERSION}"
HOME=/home/runner playwright install chromium

# Fix ownership: npx ran as root, so .cache and .npm are root-owned.
# The runner user (1001) needs to write to these at runtime.
chown -R runner:0 /home/runner/.cache 2>/dev/null || true
chown -R runner:0 /home/runner/.npm 2>/dev/null || true

echo "[RunSecure] Playwright + Chromium installed successfully."
