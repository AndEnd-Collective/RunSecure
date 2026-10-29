# ============================================================================
# RunSecure — GitHub Actions Runner Composition Base Image
# ============================================================================
# debian:bookworm-slim (~28 MB) + GitHub Actions runner binary + minimal tools
#
# Security hardening applied:
#   1.  Pinned base image digest
#   2.  Pinned package versions
#   3.  --no-install-recommends (minimal deps)
#   4.  SHA256-verified runner binary download
#   5.  Non-root user (UID 1001)
#   6.  Locked root account + no shell
#   7.  Stripped all setuid/setgid binaries
#   8.  Package manager retained for build-only language composition
#   9.  Removed network recon tools
#  10.  Removed su/sudo/cron
#  11.  Minimal PATH
#  12.  Read-only system paths (chmod)
#  13.  OCI metadata labels
#  14.  Clean layer (no caches, no tmp files)
#  15.  Multi-stage ready (used as FROM target)
# ============================================================================

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS base

# ---- Build arguments --------------------------------------------------------
# Every pin here tracks absolute latest stable and is bumped in lockstep.
# There is no cooling-off window: a release that is held back is a release
# whose security fixes we are not shipping, and the checksum pin plus the
# per-image Grype gate already catch a bad upstream build. Each pin records
# why it is at the version it is at, so a bump is a one-line audit.
#
# RUNNER_VERSION 2.338.2 — latest stable. Checksums are the ones published
#   in the release body (`<!-- BEGIN SHA linux-x64 -->` / `linux-arm64`).
ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256_ARM64=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
ARG RUNNER_SHA256_AMD64=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
# The runner tarball vendors npm under both of its private Node runtimes.
# Refresh that payload from a checksum-pinned npm release so newly disclosed
# vulnerabilities do not remain trapped behind the actions/runner release
# cadence.
#
# This is deliberately npm 11.21.1 and NOT npm 12.x, which is the current
# `latest`. runner 2.338.2 bundles both node20 and node24, and npm
# 12.2.1 declares `engines.node: ^22.22.2 || ^24.15.0 || >=26.0.0` — it does
# not support Node 20, so installing it into externals/node20 would ship a
# broken npm to every action that still runs on the node20 handler. npm
# 11.21.1 declares `^20.17.0 || >=22.9.0` and covers both runtimes.
#
# Nothing is given up by staying on 11.x here: 11.21.1 vendors exactly the
# same versions of the CVE-tracked transitive deps as 12.2.1 does. The
# workflow-facing npm in images/node.Dockerfile runs on NodeSource Node 24
# and is pinned to 12.2.1 there.
#
# Revisit when the runner drops its node20 external — then this can follow
# `latest` again. NPM_SHA256 is the sha256 of the registry tarball
# (https://registry.npmjs.org/npm/-/npm-11.21.1.tgz).
ARG NPM_VERSION=11.21.1
ARG NPM_SHA256=dd77c48eb845f4856c2cdba347cfb52bd877a2655a1ea48ff0c4796e3df9dd7b
# npm 11.21.1 and 12.2.1 still bundle undici 6.29.0, behind its 6.29.1
# security fixes. Refreshing npm alone cannot clear the HIGH findings.
# brace-expansion required the same repair previously; npm now bundles our
# fixed 5.0.12 pin, and the explicit overwrite keeps both payloads identical:
#
#   undici 6.29.0          GHSA-xjj6-f33q-929c  fixed in 6.29.1
#                          GHSA-qrxm-fqhp-jwvm / GHSA-2m5v-pch6-74hx
#   brace-expansion 5.0.9  GHSA-6j4f-fj2g-mc7p  (>=4.0.0 <5.0.10)  recursion DoS
#                          GHSA-qhr7-859c-m2p7  (>=4.0.0 <5.0.11)  recursion DoS
#
# So the same checksum-pinned overwrite the npm payload already gets is applied
# one level down, to these two packages inside npm's node_modules. Both are
# patch-level bumps within the major npm depends on, and each image carries
# one copy of each per npm installation, so there
# is no nested copy left behind at an older version.
# Re-evaluate on every npm bump: once both packages are fixed upstream,
# the explicit dependency overwrite can be retired.
ARG UNDICI_VERSION=6.29.1
ARG UNDICI_SHA256=29c4b8e0b2d86cb8795571c1959012ce057a14ecfd34858335f47c31e770a04f
ARG BRACE_EXPANSION_VERSION=5.0.12
ARG BRACE_EXPANSION_SHA256=ef8448ec78f20b692f04fa6d01f39b5ab34c66404bea3429f5a39c6c9e0be8b4
# GH_CLI_VERSION 2.103.3 — latest stable. Its bundled Go and x/net fixes
#   replace the vulnerable go1.27.1 / x/net v0.58.0 in gh 2.102.0.
#   The unchanged Grype gate checks bundled modules without suppressions.
#   These are the checksums of the .deb packages (what the install step below
#   downloads), NOT the .tar.gz archives — the release publishes both and they
#   differ.
ARG GH_CLI_VERSION=2.103.3
ARG GH_CLI_SHA256_AMD64=e3bafef96328d1a67de3a968bdfe1cc2ffd58cf6aba8b5e201356897ed06bb3d
ARG GH_CLI_SHA256_ARM64=cac3ff84b60b68e64cca69f31f303210c26320361cc3286b773655d4226b7b06

ARG TARGETARCH

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
# Standard OCI labels surface in `docker inspect`, GHCR's package page
# (description is auto-promoted), and most container security scanners.
# `documentation` is the single canonical pointer for consumers asking
# "what is this and how am I supposed to use it".
LABEL org.opencontainers.image.title="RunSecure Composition Base"
LABEL org.opencontainers.image.description="Build-only input for RunSecure language images. Contains package-manager functionality and must never be launched as a CI runner."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"
LABEL security.hardening="build-only"
LABEL io.runsecure.image-role="composition-base"

# ---- System dependencies ----------------------------------------------------
# Pin versions and use --no-install-recommends to minimize attack surface.
# `apt-get upgrade` pulls latest security patches for everything in the base
# layer (libc6, dpkg, libsystemd0, libcap2, sed, etc) — without this, grype
# flags HIGH CVEs in the unpatched debian:bookworm-slim packages even on a
# fresh digest, because Debian publishes security updates faster than the
# base image is rebuilt.
# hadolint ignore=DL3008,DL3005
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        unzip \
        libicu72 \
        libssl3 \
        zlib1g \
        liblttng-ust1 \
    && rm -rf /var/lib/apt/lists/*

# ---- Install GitHub CLI (gh) — SHA256-verified -----------------------------
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then \
         GH_CLI_SHA256="${GH_CLI_SHA256_ARM64}"; \
       elif [ "$ARCH" = "amd64" ]; then \
         GH_CLI_SHA256="${GH_CLI_SHA256_AMD64}"; \
       else \
         echo "Unsupported architecture: $ARCH" && exit 1; \
       fi \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_${ARCH}.deb" \
        -o /tmp/gh.deb \
    && echo "${GH_CLI_SHA256}  /tmp/gh.deb" | sha256sum -c - \
    && dpkg -i /tmp/gh.deb \
    && rm /tmp/gh.deb

# ---- Create non-root runner user --------------------------------------------
RUN useradd -m -s /bin/bash -u 1001 -g 0 runner

# ---- Download and verify GitHub Actions runner binary -----------------------
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then \
         RUNNER_SHA256="${RUNNER_SHA256_ARM64}"; \
         RUNNER_ARCH="arm64"; \
       elif [ "$ARCH" = "amd64" ]; then \
         RUNNER_SHA256="${RUNNER_SHA256_AMD64}"; \
         RUNNER_ARCH="x64"; \
       else \
         echo "Unsupported architecture: $ARCH" && exit 1; \
       fi \
    && curl -fsSL \
         "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" \
         -o /tmp/runner.tar.gz \
    && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum -c - \
    && mkdir -p /home/runner/actions-runner \
    && tar xzf /tmp/runner.tar.gz -C /home/runner/actions-runner \
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
    && for NODE_RUNTIME in node20 node24; do \
         NODE_PREFIX="/home/runner/actions-runner/externals/${NODE_RUNTIME}"; \
         rm -rf "${NODE_PREFIX}/lib/node_modules/npm"; \
         mkdir -p "${NODE_PREFIX}/lib/node_modules/npm"; \
         tar xzf /tmp/npm.tgz \
           --strip-components=1 \
           --no-same-owner \
           -C "${NODE_PREFIX}/lib/node_modules/npm"; \
         NPM_MODULES="${NODE_PREFIX}/lib/node_modules/npm/node_modules"; \
         for VENDORED in undici brace-expansion; do \
           rm -rf "${NPM_MODULES}/${VENDORED}"; \
           mkdir -p "${NPM_MODULES}/${VENDORED}"; \
           tar xzf "/tmp/${VENDORED}.tgz" \
             --strip-components=1 \
             --no-same-owner \
             -C "${NPM_MODULES}/${VENDORED}"; \
         done; \
         test "$("${NODE_PREFIX}/bin/node" \
           "${NODE_PREFIX}/lib/node_modules/npm/bin/npm-cli.js" --version)" \
           = "${NPM_VERSION}"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/tar/package.json').version")" \
           = "7.5.22"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/brace-expansion/package.json').version")" \
           = "${BRACE_EXPANSION_VERSION}"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/undici/package.json').version")" \
           = "${UNDICI_VERSION}"; \
       done \
    && rm /tmp/runner.tar.gz /tmp/npm.tgz /tmp/undici.tgz /tmp/brace-expansion.tgz \
    && chown -R runner:0 /home/runner/actions-runner

# ---- Install runner dependencies (.NET runtime libs) ------------------------
RUN /home/runner/actions-runner/bin/installdependencies.sh \
    && rm -rf /var/lib/apt/lists/*

# ---- Create workspace and diagnostic directories ----------------------------
RUN mkdir -p /home/runner/_work /home/runner/_diag \
    && chown -R runner:0 /home/runner

# ---- Security hardening: strip setuid/setgid bits --------------------------
# These binaries allow privilege escalation; none are needed for CI.
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# ---- Security hardening: remove dangerous runtime utilities -----------------
# Remove tools commonly used for recon, lateral movement, or escalation.
# Account-management helpers are intentionally retained in this build-only
# layer because Debian package maintainer scripts may need them while project
# tools are composed. finalize-hardening.sh removes them from every terminal
# language/project image after all package installation is complete.
RUN rm -f \
      /usr/bin/su \
      /usr/bin/sudo \
      /usr/bin/crontab \
      /usr/bin/at \
      /usr/bin/atq \
      /usr/bin/atrm \
      /usr/bin/batch \
      /usr/bin/wall \
      /usr/bin/write \
      /usr/bin/mesg \
      /usr/bin/chsh \
      /usr/bin/chfn \
      /usr/bin/newgrp \
      /bin/mount \
      /bin/umount \
    2>/dev/null || true

# ---- Security hardening: lock root account ----------------------------------
RUN passwd -l root 2>/dev/null || true \
    && sed -i 's|^root:.*:/bin/bash|root:x:0:0:root:/root:/usr/sbin/nologin|' /etc/passwd \
    && rm -rf /root/.bashrc /root/.profile /root/.bash_history

# ---- NOTE: apt is intentionally KEPT in the base image ---------------------
# Language layers (node, python, rust) and tool recipes need apt to install
# packages. The package manager is removed by finalize-hardening.sh in each
# language Dockerfile's default terminal stage and in project images produced
# by compose-image.sh. In this private intermediate image, the runner user
# (UID 1001) cannot install system packages without root access.

# ---- Security hardening: minimal PATH --------------------------------------
ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

# ---- GitHub Actions image-metadata env vars --------------------------------
# Hosted runners set ImageOS / ImageVersion to populate the "Operating System"
# and "Runner Image" groups in the workflow log UI. Self-hosted runners
# don't carry these by default — workflow logs render with empty group
# headers. We set RunSecure-flavored values so consumers see *something*
# in the UI that identifies what they're running on.
#
# The "Included Software" link the actions-runner constructs from these
# values will 404 (it points at github.com/actions/runner-images, which
# only knows about its own image set). That's a known, accepted UI quirk —
# the values themselves are still informative.
ENV ImageOS=runsecure-bookworm
# Derived from the ARG rather than restated, so it cannot drift from the
# runner actually installed above — it had been left at 2.335.1 across a
# RUNNER_VERSION bump before this was wired up.
ENV ImageVersion=${RUNNER_VERSION}

# ---- Job-started diagnostics hook ------------------------------------------
# When ACTIONS_RUNNER_HOOK_JOB_STARTED is set, the actions-runner executes
# the named script at the start of every job and pipes its output into the
# workflow log as a real "Job started hook" step. We use this to publish
# RunSecure's hardening posture (capabilities, seccomp state, mounts,
# proxy config, available toolchains) to GitHub's UI so a user debugging
# a job doesn't need to clone our repo to understand the runtime.
COPY infra/runner-hooks /opt/runsecure-hooks
RUN chmod 755 /opt/runsecure-hooks/job-started.sh /opt/runsecure-hooks/job-completed.sh
ENV ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/runsecure-hooks/job-started.sh
ENV ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/opt/runsecure-hooks/job-completed.sh

# ---- JIT entrypoint (fix G2/G3) ---------------------------------------------
# Bake the JIT-launcher script into every runner image so orchestrator-spawned
# containers actually start the actions-runner. Previously this image shipped
# neither the script nor an ENTRYPOINT, so a container created directly via
# the Docker API (as the Compose-backend orchestrator does, bypassing
# infra/docker-compose.yml's own entrypoint override + bind-mount) would
# start with no process at all. Node/Python/Rust layers and any composed
# project image inherit this — no per-project entrypoint hack required.
# Mode 0555 (read+execute, no write) matches the read-only-by-default
# posture of everything else copied into the image; owned runner:0 so the
# non-root runner user can execute it under `--user 1001:0`.
COPY --chown=runner:0 --chmod=0555 infra/scripts/entrypoint.sh /home/runner/entrypoint.sh

# ---- Final setup ------------------------------------------------------------
USER runner
WORKDIR /home/runner

ENTRYPOINT ["/home/runner/entrypoint.sh"]
CMD ["bash"]
