# ============================================================================
# RunSecure — Rust Language Layer
# ============================================================================
# Adds Rust toolchain on top of runner-base.
# Uses rustup for version management, installed under the runner user.
#
# Build:
#   docker build -f images/rust.Dockerfile \
#     --build-arg RUST_VERSION=stable \
#     -t runner-rust:stable .
# ============================================================================

ARG BASE_TAG=latest
FROM runner-base:${BASE_TAG} AS rust

ARG RUST_VERSION=stable

USER root

# Rust needs a linker and basic build tools. Install them, then strip apt.
RUN apt-get update 2>/dev/null || true \
    && apt-get install -y --no-install-recommends \
         gcc \
         libc6-dev \
         make \
         pkg-config \
         libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
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

# Switch to runner user for rustup (installs to $HOME)
USER runner

# Install rustup + toolchain as runner user (no root needed)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal \
    && . "$HOME/.cargo/env" \
    && rustc --version \
    && cargo --version

ENV PATH="/home/runner/.cargo/bin:/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

WORKDIR /home/runner
