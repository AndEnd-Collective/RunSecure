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
# NodeSource. npm 12.2.1 is latest stable and checksum-pinned.
#
# This can be 12.x while images/base.Dockerfile is held at 11.21.1 because
# this image runs NodeSource Node 24, which satisfies npm 12's
# `engines.node: ^22.22.2 || ^24.15.0 || >=26.0.0`. The base image installs
# npm into the runner's externals/node20, which does not.
ARG NPM_VERSION=12.2.1
ARG NPM_SHA256=228bd64aaef23270dbdbd2cf3d5ef5c467602ef38c4066246cef1984adab9a67
# npm 12.2.1 still bundles undici 6.29.0, behind its HIGH security fixes.
# Retain the same checksum-pinned dependency overwrite as the base image,
# including the already-fixed brace-expansion pin, so the npm payloads stay
# aligned. See images/base.Dockerfile for the advisories and removal trigger.
ARG UNDICI_VERSION=6.29.1
ARG UNDICI_SHA256=29c4b8e0b2d86cb8795571c1959012ce057a14ecfd34858335f47c31e770a04f
ARG BRACE_EXPANSION_VERSION=5.0.12
ARG BRACE_EXPANSION_SHA256=ef8448ec78f20b692f04fa6d01f39b5ab34c66404bea3429f5a39c6c9e0be8b4

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
    && curl -fsSL \
         "https://registry.npmjs.org/undici/-/undici-${UNDICI_VERSION}.tgz" \
         -o /tmp/undici.tgz \
    && echo "${UNDICI_SHA256}  /tmp/undici.tgz" | sha256sum -c - \
    && curl -fsSL \
         "https://registry.npmjs.org/brace-expansion/-/brace-expansion-${BRACE_EXPANSION_VERSION}.tgz" \
         -o /tmp/brace-expansion.tgz \
    && echo "${BRACE_EXPANSION_SHA256}  /tmp/brace-expansion.tgz" | sha256sum -c - \
    && NPM_ROOT="$(npm root --global)" \
    && rm -rf "${NPM_ROOT}/npm" \
    && mkdir -p "${NPM_ROOT}/npm" \
    && tar xzf /tmp/npm.tgz \
         --strip-components=1 \
         --no-same-owner \
         -C "${NPM_ROOT}/npm" \
    && for VENDORED in undici brace-expansion; do \
         rm -rf "${NPM_ROOT}/npm/node_modules/${VENDORED}"; \
         mkdir -p "${NPM_ROOT}/npm/node_modules/${VENDORED}"; \
         tar xzf "/tmp/${VENDORED}.tgz" \
           --strip-components=1 \
           --no-same-owner \
           -C "${NPM_ROOT}/npm/node_modules/${VENDORED}"; \
       done \
    && rm /tmp/npm.tgz /tmp/undici.tgz /tmp/brace-expansion.tgz \
    && node --version \
    && test "$(npm --version)" = "${NPM_VERSION}" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/tar/package.json').version")" \
         = "7.5.22" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/brace-expansion/package.json').version")" \
         = "${BRACE_EXPANSION_VERSION}" \
    && test "$(node -p \
         "require('${NPM_ROOT}/npm/node_modules/undici/package.json').version")" \
         = "${UNDICI_VERSION}"

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
