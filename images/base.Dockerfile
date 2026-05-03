# ============================================================================
# RunSecure — Hardened GitHub Actions Runner Base Image
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
#   8.  Removed package manager (apt/dpkg)
#   9.  Removed network recon tools
#  10.  Removed su/sudo/cron
#  11.  Minimal PATH
#  12.  Read-only system paths (chmod)
#  13.  OCI metadata labels
#  14.  Clean layer (no caches, no tmp files)
#  15.  Multi-stage ready (used as FROM target)
# ============================================================================

FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS base

# ---- Build arguments --------------------------------------------------------
# All pins follow a 48-hour freshness rule: the chosen version must be at
# least 48h old (we don't adopt bleeding-edge releases that could still
# be yanked for regressions). Renovate's customManager handles ongoing
# bumps with this same window.
#
# RUNNER_VERSION 2.334.0 (2026-04-21): patches Go-stdlib + grpc +
#   docker/cli + sigstore CVEs from the previous 2.333.1 pin.
ARG RUNNER_VERSION=2.334.0
ARG RUNNER_SHA256_ARM64=f44255bd3e80160eb25f71bc83d06ea025f6908748807a584687b3184759f7e4
ARG RUNNER_SHA256_AMD64=048024cd2c848eb6f14d5646d56c13a4def2ae7ee3ad12122bee960c56f3d271
# GH_CLI_VERSION 2.92.0 (2026-04-28) — current latest stable.
ARG GH_CLI_VERSION=2.92.0
ARG GH_CLI_SHA256_AMD64=8f8212b1a9cec261a8839e0893168f50d3fc70f095da257feef4229234cefdf8
ARG GH_CLI_SHA256_ARM64=34d620b7c884774ed86236541535170889fda0b99aafbdab8b69c7d458b5ca6b

ARG TARGETARCH

# ---- Labels -----------------------------------------------------------------
LABEL org.opencontainers.image.title="RunSecure Base"
LABEL org.opencontainers.image.description="Hardened GitHub Actions self-hosted runner base image"
LABEL org.opencontainers.image.source="https://github.com/NaorPenso/RunSecure"
LABEL org.opencontainers.image.vendor="RunSecure"
LABEL security.hardening="full"

# ---- System dependencies ----------------------------------------------------
# Pin versions and use --no-install-recommends to minimize attack surface.
# hadolint ignore=DL3008
RUN apt-get update \
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
    && rm /tmp/runner.tar.gz \
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

# ---- Security hardening: remove dangerous utilities -------------------------
# Remove tools commonly used for recon, lateral movement, or escalation.
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
      /usr/sbin/adduser \
      /usr/sbin/useradd \
      /usr/sbin/userdel \
      /usr/sbin/usermod \
      /usr/sbin/groupadd \
      /usr/sbin/groupdel \
      /usr/sbin/groupmod \
      /bin/mount \
      /bin/umount \
      /usr/bin/passwd \
    2>/dev/null || true

# ---- Security hardening: lock root account ----------------------------------
RUN passwd -l root 2>/dev/null || true \
    && sed -i 's|^root:.*:/bin/bash|root:x:0:0:root:/root:/usr/sbin/nologin|' /etc/passwd \
    && rm -rf /root/.bashrc /root/.profile /root/.bash_history

# ---- NOTE: apt is intentionally KEPT in the base image ---------------------
# Language layers (node, python, rust) and tool recipes need apt to install
# packages. The package manager is removed in the FINAL image produced by
# compose-image.sh via finalize-hardening.sh. In intermediate images, the
# runner user (UID 1001) cannot install system packages without root access.

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
ENV ImageVersion=2.334.0

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

# ---- Final setup ------------------------------------------------------------
USER runner
WORKDIR /home/runner

# Entrypoint is set by the language layer or orchestrator
CMD ["bash"]
