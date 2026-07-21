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

FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS base

# ---- Build arguments --------------------------------------------------------
# All pins follow a 48-hour freshness rule: the chosen version must be at
# least 48h old (we don't adopt bleeding-edge releases that could still
# be yanked for regressions). Renovate's customManager handles ongoing
# bumps with this same window.
#
# RUNNER_VERSION 2.335.1 (2026-06-09): background steps, Node 24 date
#   update, Docker v29.5.2 + Buildx v0.34.1, Ubuntu 26.04 compat.
ARG RUNNER_VERSION=2.335.1
ARG RUNNER_SHA256_ARM64=6d1e85bfd1a506a8b17c1f1b9b57dba458ffed90898799aaa9f599520b0d9207
ARG RUNNER_SHA256_AMD64=4ef2f25285f0ae4477f1fe1e346db76d2f3ebf03824e2ddd1973a2819bf6c8cf
# The runner tarball vendors npm under both of its private Node runtimes.
# Refresh that payload from a checksum-pinned npm release so newly disclosed
# vulnerabilities do not remain trapped behind the actions/runner release
# cadence. npm 11.18.0 (2026-06-29, beyond the 48h freshness window) supports
# both bundled Node 20 and Node 24 runtimes.
ARG NPM_VERSION=11.18.0
ARG NPM_SHA256=73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e
# GH_CLI_VERSION 2.96.0 (2026-07-02) — latest stable. Still built with
#   go1.26.4 (verified: `go version` on the released binary reports go1.26.4),
#   so it clears the older go-stdlib CVEs but NOT GO-2026-4970
#   (CVE-2026-39822, "os symlink escape", first fixed in go1.26.5). No gh
#   release ships on go1.26.5+ yet, so that one is carried as a justified
#   allow in .grype.yaml until a gh build on go1.26.5+ exists.
ARG GH_CLI_VERSION=2.96.0
ARG GH_CLI_SHA256_AMD64=11a731f4e0ca8c3db96ef6d2cc404dcab3d78247ce0e07c53e07117e7627d6a1
ARG GH_CLI_SHA256_ARM64=334dd9c6704fc1656a48e475c5a3a9aa32bbadb87fa1777513bc626af4a99e89

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
    && for NODE_RUNTIME in node20 node24; do \
         NODE_PREFIX="/home/runner/actions-runner/externals/${NODE_RUNTIME}"; \
         rm -rf "${NODE_PREFIX}/lib/node_modules/npm"; \
         mkdir -p "${NODE_PREFIX}/lib/node_modules/npm"; \
         tar xzf /tmp/npm.tgz \
           --strip-components=1 \
           --no-same-owner \
           -C "${NODE_PREFIX}/lib/node_modules/npm"; \
         test "$("${NODE_PREFIX}/bin/node" \
           "${NODE_PREFIX}/lib/node_modules/npm/bin/npm-cli.js" --version)" \
           = "${NPM_VERSION}"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/tar/package.json').version")" \
           = "7.5.19"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/brace-expansion/package.json').version")" \
           = "5.0.7"; \
         test "$("${NODE_PREFIX}/bin/node" -p \
           "require('${NODE_PREFIX}/lib/node_modules/npm/node_modules/undici/package.json').version")" \
           = "6.27.0"; \
       done \
    && rm /tmp/runner.tar.gz /tmp/npm.tgz \
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
ENV ImageVersion=2.335.1

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
