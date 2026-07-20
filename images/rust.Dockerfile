# ============================================================================
# RunSecure — Rust Language Layer
# ============================================================================
# Adds Rust toolchain on top of runner-base. The default (final) stage is a
# terminal runtime image; rust-build exists only so compose-image.sh can add
# project-requested packages/tools before applying the same final hardening.
# Uses rustup for version management, installed under the runner user.
#
# Build:
#   docker build -f images/rust.Dockerfile \
#     --build-arg RUST_VERSION=stable \
#     -t runner-rust:stable .
# ============================================================================

ARG BASE_IMAGE=runner-base
ARG BASE_TAG=latest
ARG BASE_REF=${BASE_IMAGE}:${BASE_TAG}
FROM ${BASE_REF} AS rust-build

ARG RUST_VERSION=stable

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
LABEL org.opencontainers.image.title="RunSecure Rust Composition Stage"
LABEL org.opencontainers.image.description="Build-only Rust composition input. Contains package-manager functionality and must never be launched as a CI runner."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"
LABEL security.hardening="build-only"
LABEL io.runsecure.image-role="composition"

USER root

# Rust needs a linker and basic build tools.
# Base image retains apt so language layers can install packages.
# `apt-get upgrade` pulls latest security patches for any packages whose
# transitive dependencies got pulled in at older patch levels.
RUN apt-get update \
    && apt-get upgrade -y \
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

# ---- BUILD-TIME ASSERTION ---------------------------------------------------
# Fail the build if the installed rustc channel does not match RUST_VERSION.
# Rust uses channel names (stable/beta/nightly) OR explicit versions like
# 1.78.0; rustup reports the channel for named channels and the version
# otherwise. We accept either form.
RUN . "$HOME/.cargo/env" \
    && CHANNEL=$(rustup show active-toolchain | awk '{print $1}' | cut -d'-' -f1) \
    && if [ "$CHANNEL" != "${RUST_VERSION}" ] && ! echo "$CHANNEL" | grep -qE "^${RUST_VERSION}(\$|-)"; then \
         echo "::error::Active rust toolchain is $CHANNEL but RUST_VERSION build-arg is ${RUST_VERSION}" >&2; \
         exit 1; \
       fi

ENV PATH="/home/runner/.cargo/bin:/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

# Embed the release's composition assets in the build-only stage. Versioned
# project images execute these exact bytes from the builder digest recorded on
# the terminal image; they never copy recipes from a mutable local checkout.
USER root
COPY tools/ /opt/runsecure/composition/tools/
COPY infra/scripts/finalize-hardening.sh /opt/runsecure/composition/finalize-hardening.sh
RUN find /opt/runsecure/composition/tools -type f -exec chmod 0555 {} + \
    && chmod 0555 /opt/runsecure/composition/finalize-hardening.sh

USER runner
WORKDIR /home/runner

# ---- TERMINAL RUNTIME STAGE -------------------------------------------------
# Nothing may be layered onto this stage that needs apt/dpkg or modifies /etc.
# Project composition targets rust-build above and finalizes after additions.
FROM rust-build AS rust

LABEL org.opencontainers.image.title="RunSecure Rust"
LABEL org.opencontainers.image.description="Hardened terminal GitHub Actions runner with Rust. One job per container, then destroyed."
LABEL security.hardening="full"
LABEL io.runsecure.image-role="runtime"

USER root
RUN /opt/runsecure/composition/finalize-hardening.sh \
    && rm -rf /opt/runsecure/composition

USER runner
WORKDIR /home/runner
