#!/bin/bash
# ============================================================================
# RunSecure — Finalize Image Hardening
# ============================================================================
# Called as the LAST step in the final runnable image (via compose-image.sh).
# Removes the package manager, re-strips setuid binaries, and locks /etc.
#
# This is separated from base.Dockerfile because language layers and tool
# recipes need apt during image build. Only the final image strips it.
# ============================================================================

set -euo pipefail

echo "[RunSecure] Finalizing image hardening..."

# Remove package manager so nothing can be installed at runtime
rm -rf \
    /usr/bin/apt* \
    /usr/bin/dpkg* \
    /usr/lib/apt \
    /usr/lib/dpkg \
    /var/lib/apt \
    /var/lib/dpkg \
    /var/cache/apt \
    /etc/apt \
  2>/dev/null || true

# Re-strip setuid/setgid bits (tool installs may have added new ones)
find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Lock system paths
chmod 444 /etc/passwd /etc/group 2>/dev/null || true
chmod 555 /etc 2>/dev/null || true

echo "[RunSecure] Hardening finalized."
