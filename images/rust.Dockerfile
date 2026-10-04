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

# ---- Pinned toolchain that RUST_VERSION=stable resolves to ------------------
# Rust was the one unpinned toolchain in the repo: `--default-toolchain stable`
# installed whatever rustup served that day, so the image was not reproducible
# and could change under us between two builds of the same commit.
#
# It also broke the release. Syft's binary-classifier-cataloger stopped
# recognising rustc at 1.98.0, so the toolchain vanished from the SBOM and the
# publish gate failed closed with
#   ERROR: expected runtime presence inventory is missing:
#          binary-classifier-cataloger:rust
# meaning rust CVEs would not have been scannable at all. Verified against the
# CI-pinned syft v1.48.0 by building this image at each version:
#   1.99.0  not classified
#   1.98.1  not classified
#   1.97.1  classified as rust 1.97.1   <- newest that works
#   1.96.1  classified as rust 1.96.1
#
# The pin lives here, not in the callers, because `stable` is passed in from
# publish-images.yml, smoke-test.yml, the validation and acceptance suites and
# infra/scripts/compose-image.sh (for a project asking for `runtime: rust:stable`).
# Resolving it in one place means every one of those paths gets the pinned
# toolchain without knowing the version, and consumer-facing tags stay `stable`.
#
# DO NOT bump this by hand. .github/workflows/weekly-rust-toolchain.yml tries
# the latest stable every week, builds this image with it, and only opens a
# bump PR once the scanner still inventories rust and the Grype gate passes.
ARG RUST_STABLE_PIN=1.97.1

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
    && if [ "${RUST_VERSION}" = "stable" ]; then \
         TOOLCHAIN="${RUST_STABLE_PIN}"; \
         echo "RUST_VERSION=stable resolves to pinned toolchain ${TOOLCHAIN}"; \
       else \
         TOOLCHAIN="${RUST_VERSION}"; \
       fi \
    && /tmp/rustup-init -y --default-toolchain "${TOOLCHAIN}" --profile minimal \
    && rm /tmp/rustup-init /tmp/rustup-init.sha256 \
    && . "$HOME/.cargo/env" \
    && rustc --version \
    && cargo --version

# ---- BUILD-TIME ASSERTION ---------------------------------------------------
# Fail the build if the installed toolchain is not the one we asked for.
# RUST_VERSION=stable is resolved to RUST_STABLE_PIN above, so assert against
# the resolved value — otherwise a `stable` build would compare "1.97.1"
# against "stable" and always fail. For an explicit RUST_VERSION the two are
# the same. rustup reports e.g. "1.97.1-aarch64-unknown-linux-gnu", so compare
# on the leading version/channel component.
RUN . "$HOME/.cargo/env" \
    && if [ "${RUST_VERSION}" = "stable" ]; then \
         EXPECTED="${RUST_STABLE_PIN}"; \
       else \
         EXPECTED="${RUST_VERSION}"; \
       fi \
    && ACTIVE=$(rustup show active-toolchain | awk '{print $1}') \
    && if ! echo "$ACTIVE" | grep -qE "^${EXPECTED}(\$|-)"; then \
         echo "::error::Active rust toolchain is $ACTIVE but expected ${EXPECTED} (RUST_VERSION=${RUST_VERSION})" >&2; \
         exit 1; \
       fi \
    && if ! rustc --version | grep -qF "${EXPECTED}"; then \
         echo "::error::rustc --version does not report ${EXPECTED}: $(rustc --version)" >&2; \
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
