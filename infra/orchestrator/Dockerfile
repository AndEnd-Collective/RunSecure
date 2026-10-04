# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RUNSECURE_VERSION=dev
ARG RUNSECURE_BUILD_SHA=unknown
RUN CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${RUNSECURE_VERSION} -X main.buildSHA=${RUNSECURE_BUILD_SHA}" \
      -o /out/orchestrator ./cmd/orchestrator

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/orchestrator /usr/local/bin/orchestrator
USER nonroot:nonroot
HEALTHCHECK --interval=15s --timeout=2s --retries=3 \
  CMD ["/usr/local/bin/orchestrator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/orchestrator"]
