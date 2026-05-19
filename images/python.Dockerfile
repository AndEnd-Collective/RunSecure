# ============================================================================
# RunSecure — Python Language Layer
# ============================================================================
# Adds Python runtime on top of runner-base.
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
FROM ${BASE_IMAGE}:${BASE_TAG} AS python

ARG PYTHON_VERSION=3.12

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
LABEL org.opencontainers.image.title="RunSecure Python"
LABEL org.opencontainers.image.description="Hardened ephemeral GitHub Actions runner with Python (astral-sh/python-build-standalone, SHA256-verified). One job per container, then destroyed. See documentation for proper usage."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"
LABEL security.hardening="full"

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
            PY_FULL=3.12.13; PBS_TAG=20260510; \
            SHA_AMD64=e7332b4b4bb85006deb48d251c786a04c14de104c9b3a006b33457a4a604b8bc; \
            SHA_ARM64=87097de12bc212e41ea8409efd0083fe06465d725e35d130e4007a4bf7e4f1c8 ;; \
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

USER runner
WORKDIR /home/runner
