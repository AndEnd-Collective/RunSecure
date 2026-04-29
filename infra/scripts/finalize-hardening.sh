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

# M10: every operation below was previously suffixed with `2>/dev/null
# || true`, which converted any failure (read-only filesystem, missing
# binary path, immutable bit set) into a silent success — the script
# would then claim "Hardening finalized" without having actually done
# anything. With set -euo pipefail and the masks removed, an unexpected
# failure now aborts the image build instead of producing a degraded
# image that the operator believes is hardened.

# Remove package manager so nothing can be installed at runtime.
# rm -rf with -f returns 0 for non-existent paths, so this is safe to
# run even on images where apt was already stripped earlier.
rm -rf \
    /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
    /usr/bin/apt-key /usr/bin/apt-mark /usr/bin/aptitude \
    /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/dpkg-divert /usr/bin/dpkg-query \
    /usr/bin/dpkg-split /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger \
    /usr/lib/apt \
    /usr/lib/dpkg \
    /var/lib/apt \
    /var/lib/dpkg \
    /var/cache/apt \
    /etc/apt

# Re-strip setuid/setgid bits added by any tool install. Use -print0 |
# xargs -0 -r so an unreadable filesystem entry on `find`'s walk does
# NOT mask a chmod failure on a real binary (which is what we care
# about). xargs propagates chmod's exit code.
find / -xdev -perm /6000 -type f -print0 2>/dev/null | xargs -0 -r chmod a-s

# Lock system paths. These MUST succeed on a normal Debian/Alpine base
# — any failure here means the image is not properly hardened and the
# build should abort.
chmod 444 /etc/passwd /etc/group
chmod 555 /etc

# Belt-and-suspenders: verify the binaries we tried to remove are
# really gone, in case a future apt+/dpkg+ glob expansion regresses.
for bin in apt apt-get dpkg dpkg-query; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo "[RunSecure] ERROR: $bin still on PATH after finalize-hardening — refusing to produce a degraded image" >&2
        exit 1
    fi
done

echo "[RunSecure] Hardening finalized."
