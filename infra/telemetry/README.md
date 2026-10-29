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

Canonical Go sources and tests live here. Generated copies under each
consumer's `internal/telemetry` retain isolated Docker/module build contexts:

```sh
python3 infra/scripts/validate/sync-telemetry.py
python3 infra/scripts/validate/sync-telemetry.py --check
bash tests/validation/test-telemetry-mirrors.sh
go test -race ./... # from this directory
```

The sync check compares every Go source/test byte and rejects foreign Go files.
CI tests the canonical source and checks its copies; consumer coverage gates
exercise the same tests inside each module. Do not edit a generated copy.
