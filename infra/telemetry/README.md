# Maintained telemetry helper

This is RunSecure's standard-library-only emission support, not an upstream SDK.
It enriches controller events from explicit non-secret identity variables,
redacts recognizable credentials and sensitive structured keys, preserves large
JSON integers, and detects failed or short event writes. Callers retain typed
operational events and their project-local registry definition UUIDs.

`k8s.context` identifies the emitting process Pod. It must not be confused with
the job Pod described by legacy spawn fields. No metadata endpoint, Kubernetes
API, credential file or general environment enumeration is used for enrichment.
Redaction is defense in depth: never pass request bodies, arbitrary application
output or complete credential-bearing configuration into a controller event.

This module is the only copy. The orchestrator, socket-proxy and collector
processor modules `require` it and `replace` it by relative path
(`../telemetry`, `../../telemetry`). Image builds keep each component's
own module as the build context and add this directory as the `telemetry`
named context:

```sh
docker build --build-context telemetry=infra/telemetry \
  -f infra/orchestrator/Dockerfile infra/orchestrator
```

The OCB-generated collector distribution is a separate main module, so
`infra/collector/builder-config.yaml` repeats the replace. Verify with:

```sh
bash tests/validation/test-telemetry-single-source.sh
go test -race ./... # from this directory
```
