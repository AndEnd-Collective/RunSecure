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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/socket-proxy /usr/local/bin/socket-proxy
COPY allowed-images.txt /etc/runsecure/socket-proxy/allowed-images.txt
USER nonroot:nonroot
EXPOSE 2375
ENTRYPOINT ["/usr/local/bin/socket-proxy"]
