# ============================================================================
# RunSecure — Node.js Language Layer
# ============================================================================
# Adds Node.js runtime on top of runner-base. The default (final) stage is a
# terminal runtime image; node-build exists only so compose-image.sh can add
# project-requested packages/tools before applying the same final hardening.
# Uses NodeSource for version-pinned installs.
#
# Build:
#   docker build -f images/node.Dockerfile \
#     --build-arg NODE_VERSION=24 \
#     -t runner-node:24 .
# ============================================================================

ARG BASE_IMAGE=runner-base
ARG BASE_TAG=latest
ARG BASE_REF=${BASE_IMAGE}:${BASE_TAG}
FROM ${BASE_REF} AS node-build

ARG NODE_VERSION=24
# Keep the workflow-facing npm independent from the version bundled by
# NodeSource. npm 11.18.0 (2026-06-29, beyond the 48h freshness window) is
# checksum-pinned and contains fixed tar, brace-expansion, and undici.
ARG NPM_VERSION=11.18.0
ARG NPM_SHA256=73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
LABEL org.opencontainers.image.title="RunSecure Node.js Composition Stage"
LABEL org.opencontainers.image.description="Build-only Node.js composition input. Contains package-manager functionality and must never be launched as a CI runner."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"
LABEL security.hardening="build-only"
LABEL io.runsecure.image-role="composition"

USER root

# Install Node.js from NodeSource using GPG-verified apt repo (no pipe-to-bash).
# gnupg is needed to dearmor the signing key; removed after setup.
# `apt-get upgrade` is repeated here (also in base) because NodeSource's repo
# can pull in transitive deps at older patch levels that need re-upgrading.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_VERSION}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get upgrade -y \
    && apt-get purge -y --auto-remove gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL \
         "https://registry.npmjs.org/npm/-/npm-${NPM_VERSION}.tgz" \
         -o /tmp/npm.tgz \
    && echo "${NPM_SHA256}  /tmp/npm.tgz" | sha256sum -c - \
    && NPM_ROOT="$(npm root --global)" \
    && rm -rf "${NPM_ROOT}/npm" \
    && mkdir -p "${NPM_ROOT}/npm" \
    && tar xzf /tmp/npm.tgz \
         --strip-components=1 \
         --no-same-owner \
         -C "${NPM_ROOT}/npm" \
    && rm /tmp/npm.tgz \
    && node --version \
    && test "$(npm --version)" = "${NPM_VERSION}" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/tar/package.json').version")" \
         = "7.5.19" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/brace-expansion/package.json').version")" \
         = "5.0.7" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/undici/package.json').version")" \
         = "6.27.0"

# ---- BUILD-TIME ASSERTION ---------------------------------------------------
# Fail the build if the installed Node major version does not match
# NODE_VERSION. Prevents the kind of tag-vs-reality drift that hit python.
RUN INSTALLED_MAJOR=$(node -p 'process.versions.node.split(".")[0]') \
    && if [ "$INSTALLED_MAJOR" != "${NODE_VERSION}" ]; then \
         echo "::error::Installed Node major is $INSTALLED_MAJOR but NODE_VERSION build-arg is ${NODE_VERSION}" >&2; \
         exit 1; \
       fi

# Re-apply setuid stripping (NodeSource may add new binaries)
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

# Embed the release's composition assets in the build-only stage. Versioned
# project images execute these exact bytes from the builder digest recorded on
# the terminal image; they never copy recipes from a mutable local checkout.
COPY tools/ /opt/runsecure/composition/tools/
COPY infra/scripts/finalize-hardening.sh /opt/runsecure/composition/finalize-hardening.sh
RUN find /opt/runsecure/composition/tools -type f -exec chmod 0555 {} + \
    && chmod 0555 /opt/runsecure/composition/finalize-hardening.sh

USER runner
WORKDIR /home/runner

# ---- TERMINAL RUNTIME STAGE -------------------------------------------------
# Nothing may be layered onto this stage that needs apt/dpkg or modifies /etc.
# Project composition targets node-build above and finalizes after its additions.
FROM node-build AS node

LABEL org.opencontainers.image.title="RunSecure Node.js"
LABEL org.opencontainers.image.description="Hardened terminal GitHub Actions runner with Node.js. One job per container, then destroyed."
LABEL security.hardening="full"
LABEL io.runsecure.image-role="runtime"

USER root
RUN /opt/runsecure/composition/finalize-hardening.sh \
    && rm -rf /opt/runsecure/composition

USER runner
WORKDIR /home/runner
