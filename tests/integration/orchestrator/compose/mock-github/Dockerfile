# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mock-github .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mock-github /usr/local/bin/mock-github
USER nonroot:nonroot
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/mock-github"]
