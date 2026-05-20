# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o /out/orchestrator ./cmd/orchestrator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/orchestrator /usr/local/bin/orchestrator
USER nonroot:nonroot
HEALTHCHECK --interval=15s --timeout=2s --retries=3 \
  CMD ["/usr/local/bin/orchestrator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/orchestrator"]
