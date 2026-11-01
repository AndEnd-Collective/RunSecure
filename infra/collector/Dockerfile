# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache git
WORKDIR /build
# BuildKit context is the independently authorized, pinned PRIVATE checkout.
# It is never copied into the final image or committed to this public repo.
COPY --from=cornerstone-src / /build/cornerstone-src/otel-collector/
COPY infra/collector/processor /build/public-processor/
COPY infra/telemetry /build/telemetry/
COPY infra/collector/builder-config.yaml /build/builder-config.yaml
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install go.opentelemetry.io/collector/cmd/builder@v0.164.0 && \
    test "$(builder version 2>&1)" = "ocb version v0.164.0" && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} builder --skip-strict-versioning=false --config=/build/builder-config.yaml

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS native-runtime
# Journald receiver invokes a real journalctl. Its journal-format compatibility
# with the selected Bottlerocket release is a live commissioning requirement.
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates systemd && \
    journalctl --version && \
    rm -rf /var/lib/apt/lists/*
# Debian's 2026-10-20 security backport removes the distrusted emSign ECC G3
# and Comodo AAA roots; require that package floor before copying to scratch.
RUN ca_version="$(dpkg-query -W -f='${Version}' ca-certificates)" && \
    dpkg --compare-versions "$ca_version" ge '20250419+deb13u1' && \
    dpkg-query -W ca-certificates && test -s /etc/ssl/certs/ca-certificates.crt

# No shell, package manager, journal tool or native runtime enters the gateway.
FROM scratch AS gateway
COPY --from=native-runtime /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chmod=0555 /build/dist/runsecure-collector /usr/local/bin/runsecure-collector
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/runsecure-collector"]

# journalctl's shared-library closure, plus the LZ4/XZ decompressors systemd
# dlopens to read compressed journal objects. Each owning package's dpkg
# status stanza travels with its files, and os-release identifies the distro,
# so scanners keep both the inventory and the advisories that match it.
FROM native-runtime AS journal-closure
RUN set -eu; \
    mkdir -p /closure/var/lib/dpkg/status.d; \
    for merged in /lib /lib64; do [ ! -L "$merged" ] || cp -a "$merged" "/closure$merged"; done; \
    cp -a --parents /etc/os-release "$(readlink -f /etc/os-release)" /closure/; \
    files="/usr/bin/journalctl $(ldd /usr/bin/journalctl | awk '$2 == "=>" {print $3} $1 ~ /^\/.*ld-linux/ {print $1}')"; \
    for lib in liblz4.so.1 liblzma.so.5; do \
      files="$files $(dpkg -L "$(dpkg -S "*/$lib" | cut -d: -f1 | head -n1)" | grep "/$lib\$")"; \
    done; \
    : > /tmp/closure-owners; \
    for f in $files; do \
      link="$(readlink -f "$(dirname "$f")")/$(basename "$f")"; \
      real="$(readlink -f "$f")"; \
      cp -a --parents "$link" /closure/; \
      cp -a --parents "$real" /closure/; \
      owner="$(dpkg -S "$real" 2>/dev/null || dpkg -S "$link")"; \
      echo "${owner%%:*}" >> /tmp/closure-owners; \
    done; \
    sort -u /tmp/closure-owners > /tmp/closure-packages; \
    test "$(wc -l < /tmp/closure-packages)" -ge 10; \
    while read -r pkg; do dpkg-query -s "$pkg" > "/closure/var/lib/dpkg/status.d/$pkg"; done < /tmp/closure-packages; \
    cat /tmp/closure-packages

# No shell, package manager or tool outside journalctl's closure enters the node.
FROM scratch AS node
COPY --from=journal-closure /closure/ /
COPY --from=native-runtime /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chmod=0555 /build/dist/runsecure-collector /usr/local/bin/runsecure-collector
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/runsecure-collector"]
