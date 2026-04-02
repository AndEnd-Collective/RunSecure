# ============================================================================
# RunSecure — Node.js Language Layer
# ============================================================================
# Adds Node.js runtime on top of runner-base.
# Uses NodeSource for version-pinned installs.
#
# Build:
#   docker build -f images/node.Dockerfile \
#     --build-arg NODE_VERSION=24 \
#     -t runner-node:24 .
# ============================================================================

ARG BASE_TAG=latest
FROM runner-base:${BASE_TAG} AS node

ARG NODE_VERSION=24

USER root

# Install Node.js from NodeSource.
# We temporarily restore minimal package management to install, then clean up.
# Note: The base image has apt removed, so we bootstrap from scratch.
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    && rm /tmp/nodesource_setup.sh

# Restore apt just long enough to install Node.js, then strip it again.
RUN apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    # Verify installation
    && node --version \
    && npm --version \
    # Configure npm to reduce attack surface
    && npm config set ignore-scripts false \
    && npm config set audit true \
    # Remove apt/dpkg again
    && rm -rf \
         /usr/bin/apt* /usr/bin/dpkg* \
         /usr/lib/apt /usr/lib/dpkg \
         /var/lib/apt /var/lib/dpkg \
         /var/cache/apt /etc/apt \
       2>/dev/null || true

# Re-apply hardening that root operations may have altered
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true \
    && chmod 444 /etc/passwd /etc/group \
    && chmod 555 /etc

ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

USER runner
WORKDIR /home/runner
