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

ARG BASE_IMAGE=runner-base
ARG BASE_TAG=latest
FROM ${BASE_IMAGE}:${BASE_TAG} AS node

ARG NODE_VERSION=24

USER root

# Install Node.js from NodeSource using GPG-verified apt repo (no pipe-to-bash).
# gnupg is needed to dearmor the signing key; removed after setup.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_VERSION}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y --auto-remove gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && node --version \
    && npm --version

# Re-apply setuid stripping (NodeSource may add new binaries)
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

USER runner
WORKDIR /home/runner
