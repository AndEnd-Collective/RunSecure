# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26

# Build stage. CI uses buildx for multi-arch via --platform=$BUILDPLATFORM
# and TARGETOS/TARGETARCH; on a local docker build without buildx the
# native platform is used implicitly. Both paths produce a static binary.
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' \
    -o /out/socket-proxy ./cmd/socket-proxy

FROM gcr.io/distroless/static-debian12:latest@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160
COPY --from=build /out/socket-proxy /usr/local/bin/socket-proxy
COPY allowed-images.txt /etc/runsecure/socket-proxy/allowed-images.txt
# Runs as root by necessity: /var/run/docker.sock on Docker Desktop / Colima
# is owned by root:root (mode 600), so a nonroot container can't read it.
# Strictness is maintained via the compose stack's runtime hardening:
#   cap_drop: ALL, no-new-privileges, read_only rootfs, seccomp profile.
# Running as root inside a container with all capabilities dropped is
# functionally equivalent to nonroot for the threats this design defends
# against (host escape, privileged ops); the actual exposure surface is
# bounded by the strict Docker API allowlist enforced by this binary.
USER 0:0
EXPOSE 2375
ENTRYPOINT ["/usr/local/bin/socket-proxy"]
