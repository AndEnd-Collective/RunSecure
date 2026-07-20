# ============================================================================
# RunSecure — Python Language Layer
# ============================================================================
# Adds Python runtime on top of runner-base. The default (final) stage is a
# terminal runtime image; python-build exists only so compose-image.sh can add
# project-requested packages/tools before applying the same final hardening.
#
# We DO NOT use Debian's `python3` package because Debian Bookworm ships
# 3.11.2 — installing it would silently make `runner-python:3.12` ship 3.11,
# which is a security misrepresentation (consumers picking the image by tag
# expect 3.12). Instead we install astral-sh's python-build-standalone
# tarballs (the same artifacts `uv python install` uses): SHA256-verified,
# portable, and pinned to a specific patch version.
#
# Build:
#   docker build -f images/python.Dockerfile \
#     --build-arg PYTHON_VERSION=3.12 \
#     -t runner-python:3.12 .
#
# Adding a new minor version (e.g. 3.13):
#   1. Find a python-build-standalone release containing it at
#      https://github.com/astral-sh/python-build-standalone/releases
#   2. Add a new case branch below with the full version + release tag.
#   3. Add SHA256s for x86_64 + aarch64 from that release's SHA256SUMS.
#   4. Add to the publish-images.yml matrix.
# ============================================================================

ARG BASE_IMAGE=runner-base
ARG BASE_TAG=latest
ARG BASE_REF=${BASE_IMAGE}:${BASE_TAG}
FROM ${BASE_REF} AS python-build

ARG PYTHON_VERSION=3.12

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
LABEL org.opencontainers.image.title="RunSecure Python Composition Stage"
LABEL org.opencontainers.image.description="Build-only Python composition input. Contains package-manager functionality and must never be launched as a CI runner."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"
LABEL security.hardening="build-only"
LABEL io.runsecure.image-role="composition"

USER root

# `apt-get upgrade` pulls latest security patches; no Python packages from
# Debian since we install a standalone build below.
# hadolint ignore=DL3008,DL3005
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Install Python from astral-sh/python-build-standalone (signed tarball,
# SHA256-verified). Maps the requested minor version (3.12) onto a known
# patch + release tag. Build fails if PYTHON_VERSION is unsupported.
RUN ARCH_DEB=$(dpkg --print-architecture) \
    && case "$ARCH_DEB" in \
         amd64) ARCH_TRIPLE="x86_64-unknown-linux-gnu" ;; \
         arm64) ARCH_TRIPLE="aarch64-unknown-linux-gnu" ;; \
         *) echo "Unsupported architecture: $ARCH_DEB" && exit 1 ;; \
       esac \
    && case "${PYTHON_VERSION}" in \
         3.12) \
            PY_FULL=3.12.13; PBS_TAG=20260610; \
            SHA_AMD64=c218f50baeb2c06a30c2f03db5986b2bad6ab7c8a52faad2d5a59bda0677b93a; \
            SHA_ARM64=bc74cf1bb517651868342b0619b21eaaf9f94a2022c9c61886dd980e16fb091b ;; \
         *) echo "Unsupported PYTHON_VERSION: ${PYTHON_VERSION}" && exit 1 ;; \
       esac \
    && if [ "$ARCH_DEB" = "amd64" ]; then EXPECTED_SHA="$SHA_AMD64"; else EXPECTED_SHA="$SHA_ARM64"; fi \
    && curl -fsSL \
         "https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/cpython-${PY_FULL}+${PBS_TAG}-${ARCH_TRIPLE}-install_only.tar.gz" \
         -o /tmp/python.tar.gz \
    && echo "${EXPECTED_SHA}  /tmp/python.tar.gz" | sha256sum -c - \
    && mkdir -p /opt \
    && tar -xzf /tmp/python.tar.gz -C /opt \
    && rm /tmp/python.tar.gz \
    && ln -sf /opt/python/bin/python3 /usr/local/bin/python3 \
    && ln -sf /opt/python/bin/python3 /usr/local/bin/python \
    && ln -sf /opt/python/bin/pip3 /usr/local/bin/pip3 \
    && ln -sf /opt/python/bin/pip3 /usr/local/bin/pip

# ---- BUILD-TIME ASSERTION ---------------------------------------------------
# Fails the build if the installed Python's minor version does not match the
# PYTHON_VERSION build-arg. This prevents regressions like the pre-v1.1.5 bug
# where the image was tagged `runner-python:3.12` but actually shipped 3.11.
RUN INSTALLED=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') \
    && if [ "$INSTALLED" != "${PYTHON_VERSION}" ]; then \
         echo "::error::Installed Python is $INSTALLED but PYTHON_VERSION build-arg is ${PYTHON_VERSION}" >&2; \
         exit 1; \
       fi \
    && python3 --version \
    && pip3 --version

# Re-apply setuid stripping
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
# Project composition targets python-build above and finalizes after additions.
FROM python-build AS python

LABEL org.opencontainers.image.title="RunSecure Python"
LABEL org.opencontainers.image.description="Hardened terminal GitHub Actions runner with Python. One job per container, then destroyed."
LABEL security.hardening="full"
LABEL io.runsecure.image-role="runtime"

USER root
RUN /opt/runsecure/composition/finalize-hardening.sh \
    && rm -rf /opt/runsecure/composition

USER runner
WORKDIR /home/runner
