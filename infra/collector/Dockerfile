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
COPY infra/collector/builder-config.yaml /build/builder-config.yaml
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install go.opentelemetry.io/collector/cmd/builder@v0.158.0 && \
    test "$(builder version 2>&1)" = "ocb version v0.158.0" && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} builder --skip-strict-versioning=false --config=/build/builder-config.yaml

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
# Journald receiver invokes a real journalctl. Its journal-format compatibility
# with the selected Bottlerocket release is a live commissioning requirement.
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates systemd && \
    journalctl --version && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder --chmod=0555 /build/dist/runsecure-collector /usr/local/bin/runsecure-collector
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/runsecure-collector"]
