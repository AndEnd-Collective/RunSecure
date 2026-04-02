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
# Base image retains apt so language layers can install packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         python3 \
         python3-pip \
         python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && python3 --version \
    && pip3 --version

# Re-apply setuid stripping
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

USER runner
WORKDIR /home/runner
