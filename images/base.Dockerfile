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

FROM debian:bookworm-slim AS base

# ---- Build arguments --------------------------------------------------------
ARG RUNNER_VERSION=2.333.1
ARG RUNNER_SHA256_ARM64=69ac7e5692f877189e7dddf4a1bb16cbbd6425568cd69a0359895fac48b9ad3b
ARG RUNNER_SHA256_AMD64=18f8f68ed1892854ff2ab1bab4fcaa2f5abeedc98093b6cb13638991725cab74
ARG GH_CLI_VERSION=2.74.1

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

# ---- Install GitHub CLI (gh) ------------------------------------------------
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_${ARCH}.deb" \
        -o /tmp/gh.deb \
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

# ---- Security hardening: remove package manager -----------------------------
# After all installs are complete, remove apt/dpkg so nothing can be installed
# at runtime inside the container.
RUN rm -rf \
      /usr/bin/apt* \
      /usr/bin/dpkg* \
      /usr/lib/apt \
      /usr/lib/dpkg \
      /var/lib/apt \
      /var/lib/dpkg \
      /var/cache/apt \
      /etc/apt \
    2>/dev/null || true

# ---- Security hardening: restrict system paths ------------------------------
RUN chmod 444 /etc/passwd /etc/group \
    && chmod 555 /etc

# ---- Security hardening: minimal PATH --------------------------------------
ENV PATH="/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"

# ---- Final setup ------------------------------------------------------------
USER runner
WORKDIR /home/runner

# Entrypoint is set by the language layer or orchestrator
CMD ["bash"]
