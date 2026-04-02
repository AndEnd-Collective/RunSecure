# ============================================================================
# RunSecure — Python Language Layer
# ============================================================================
# Adds Python runtime on top of runner-base.
# Installs from Debian packages (no pyenv/conda bloat).
#
# Build:
#   docker build -f images/python.Dockerfile \
#     --build-arg PYTHON_VERSION=3.12 \
#     -t runner-python:3.12 .
# ============================================================================

ARG BASE_TAG=latest
FROM runner-base:${BASE_TAG} AS python

ARG PYTHON_VERSION=3.12

USER root

# Install Python and pip.
# Debian bookworm ships Python 3.11; for other versions, use deadsnakes-style
# packages or build from source in a builder stage.
RUN apt-get update 2>/dev/null || true \
    && apt-get install -y --no-install-recommends \
         python3 \
         python3-pip \
         python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    # Create a symlink so `python` works
    && ln -sf /usr/bin/python3 /usr/bin/python \
    # Verify installation
    && python3 --version \
    && pip3 --version \
    # Remove apt/dpkg again
    && rm -rf \
         /usr/bin/apt* /usr/bin/dpkg* \
         /usr/lib/apt /usr/lib/dpkg \
         /var/lib/apt /var/lib/dpkg \
         /var/cache/apt /etc/apt \
       2>/dev/null || true

# Re-apply hardening
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true \
    && chmod 444 /etc/passwd /etc/group \
    && chmod 555 /etc

ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

USER runner
WORKDIR /home/runner
