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

# Cypress system dependencies (headless mode).
# Notes:
#   - DEBIAN_FRONTEND=noninteractive avoids debconf prompts.
#   - policy-rc.d prevents post-install scripts from trying to start services
#     (libpam-systemd, dbus-user-session etc. cannot fully configure in a
#     containerized build with no running init system on arm64).
#   - We install libgtk2.0-0 (sufficient for Cypress headless) and
#     deliberately omit libgtk-3-0 / dbus-user-session / dconf-service —
#     including those drags in systemd-integration packages that fail to
#     configure on arm64 build hosts. Cypress runs fine with GTK2 only.
export DEBIAN_FRONTEND=noninteractive
echo 'exit 101' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
# Install in two phases:
#  1. Base GTK + Electron deps that DON'T pull systemd integrations.
#  2. libgtk-3-0 which DOES pull dbus-user-session/dconf-service. With
#     policy-rc.d in place those packages can't start their services,
#     and dpkg --configure -a at the end finishes any deferred setup.
apt-get install -y --no-install-recommends \
    libgtk2.0-0 \
    libgbm-dev \
    libnotify-bin \
    libnss3 \
    libxss1 \
    libasound2 \
    libxtst6 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libpango-1.0-0 \
    libcairo2 \
    xauth \
    xvfb
# libgtk-3-0 (and its dconf/dbus dependency chain). Allow configure failures;
# the .so files we need are already unpacked even if a postinst script can't
# complete. The final `dpkg --configure -a` retries everything.
apt-get install -y --no-install-recommends libgtk-3-0 || true
# Finish any deferred configuration; if anything is still half-configured,
# treat that as non-fatal — the relevant library files are already present.
dpkg --configure -a 2>/dev/null || true
rm -f /usr/sbin/policy-rc.d
rm -rf /var/lib/apt/lists/*

# H9: pin Cypress version. Floating `npm i -g cypress` builds a
# different image every time the recipe runs, which (a) defeats image
# determinism, (b) silently absorbs upstream supply-chain changes, and
# (c) means a regression in a new Cypress release immediately affects
# every user. Renovate updates this constant as a tracked PR so the
# upgrade is visible.
# renovate: datasource=npm depName=cypress
# 15.14.1 (2026-04-21): 15.14.2 from 2026-04-29 is inside the 48h gate.
CYPRESS_VERSION="15.14.1"
npm install -g "cypress@${CYPRESS_VERSION}"
HOME=/home/runner cypress install
# Note: `cypress verify` is intentionally NOT run during image build.
#   Cypress 14+ on arm64 hangs in `--smoke-test` even under xvfb-run because
#   the headless smoke-test attempts to talk to the GPU stack which is not
#   available in a build-time container. Workflows will run their own
#   `cypress run` invocation when needed; binary integrity is verified at
#   that point. Image consumers can also explicitly run `cypress verify`
#   inside an xvfb-run session in their workflow if they want extra
#   confidence.

# Cypress's cache is owned by root after `npm install -g`; chown to runner
# so the unprivileged runtime user can read it.
chown -R runner:0 /home/runner/.cache 2>/dev/null || true

echo "[RunSecure] Cypress installed successfully."
