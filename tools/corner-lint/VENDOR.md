# Vendored: corner-lint

This directory vendors the `corner-lint` CLI from
`github.com/Cerebras/Cornerstone/corner-lint` (Apache-2.0).

## Why it's vendored

The upstream repo is private, so the CI workflow can't clone it without a
PAT. Vendoring the source keeps `cornerstone-validate` working with zero
runtime auth.

## How to refresh

```sh
src=/path/to/Cornerstone/corner-lint
rm -rf tools/corner-lint/{cmd,internal,go.mod,go.sum}
cp -R "$src"/{cmd,internal,go.mod,go.sum,LICENSE} tools/corner-lint/
```

The `tools/corner-lint/` directory is its own Go module
(`github.com/Cerebras/Cornerstone/corner-lint`) — independent of the
orchestrator and socket-proxy modules.
