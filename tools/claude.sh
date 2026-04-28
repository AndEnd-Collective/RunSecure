#!/bin/bash
# ============================================================================
# RunSecure Tool Recipe — Claude Code CLI
# ============================================================================
# Installs the official Claude Code CLI binary so workflows that use
# `anthropics/claude-code-action@v1` (which spawns `/home/runner/.local/bin/claude`)
# can run inside RunSecure.
#
# Requirements: Node.js or any base image with curl + bash.
# Image size impact: ~80 MB (single statically-linked binary + downloads cache).
# ============================================================================

set -euo pipefail

# claude.ai/install.sh writes to $HOME/.local/bin and $HOME/.claude. Run as
# root but with HOME redirected to the runner user's home so the binary lands
# at /home/runner/.local/bin/claude — exactly where claude-code-action expects.
HOME=/home/runner bash -c 'curl -fsSL https://claude.ai/install.sh | bash'

# The install ran as root, so the resulting files are root-owned. The runner
# user (UID 1001) needs to execute the binary at runtime — match the
# ownership pattern used by playwright.sh.
chown -R runner:0 /home/runner/.local 2>/dev/null || true
chown -R runner:0 /home/runner/.claude 2>/dev/null || true

# Verify install succeeded and is invocable as the runner user.
HOME=/home/runner /home/runner/.local/bin/claude --version

echo "[RunSecure] Claude Code CLI installed successfully."
