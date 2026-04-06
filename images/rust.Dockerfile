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

ARG BASE_IMAGE=runner-base
ARG BASE_TAG=latest
FROM ${BASE_IMAGE}:${BASE_TAG} AS rust

ARG RUST_VERSION=stable

USER root

# Rust needs a linker and basic build tools.
# Base image retains apt so language layers can install packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         gcc \
         libc6-dev \
         make \
         pkg-config \
         libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Re-apply setuid stripping
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Switch to runner user for rustup (installs to $HOME)
USER runner

# Install rustup + toolchain as runner user (no pipe-to-sh).
# Downloads the rustup-init binary directly and verifies its SHA256 checksum
# against the upstream-published checksum file.
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then RUSTUP_ARCH="aarch64-unknown-linux-gnu"; \
       elif [ "$ARCH" = "amd64" ]; then RUSTUP_ARCH="x86_64-unknown-linux-gnu"; \
       else echo "Unsupported architecture: $ARCH" && exit 1; fi \
    && curl --proto '=https' --tlsv1.2 -sSf \
         "https://static.rust-lang.org/rustup/dist/${RUSTUP_ARCH}/rustup-init" \
         -o /tmp/rustup-init \
    && curl --proto '=https' --tlsv1.2 -sSf \
         "https://static.rust-lang.org/rustup/dist/${RUSTUP_ARCH}/rustup-init.sha256" \
         -o /tmp/rustup-init.sha256 \
    && cd /tmp && sha256sum -c rustup-init.sha256 \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --default-toolchain "${RUST_VERSION}" --profile minimal \
    && rm /tmp/rustup-init /tmp/rustup-init.sha256 \
    && . "$HOME/.cargo/env" \
    && rustc --version \
    && cargo --version

ENV PATH="/home/runner/.cargo/bin:/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

WORKDIR /home/runner
