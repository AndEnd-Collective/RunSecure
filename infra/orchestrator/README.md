# RunSecure Orchestrator (Compose backend)

Distroless Go binary that polls GitHub for queued workflow runs and spawns
ephemeral hardened runner containers (or Pods) on demand via a custom Go
docker-socket-proxy (Compose backend) or Kubernetes client (Kubernetes
backend). For the full design see
`docs/superpowers/specs/2026-05-19-persistent-local-runners-design.md`.

## Quickstart

```sh
# 1. Build images locally (or pull from GHCR).
docker build -t runsecure-socket-proxy:local infra/socket-proxy
docker build -t runsecure-orchestrator:local  infra/orchestrator

# 2. Copy the scope template and edit it.
cp infra/orchestrator/scopes/example.yml infra/orchestrator/scopes/my.yml

# 3. Create a per-scope .env (paths to images + PAT secret).
cat > infra/orchestrator/scopes/my.env <<EOF
RUNSECURE_SCOPE=my
RUNSECURE_SOCKET_PROXY_IMAGE=runsecure-socket-proxy:local
RUNSECURE_ORCHESTRATOR_IMAGE=runsecure-orchestrator:local
RUNSECURE_PROXY_IMAGE=ghcr.io/andend-collective/runsecure/proxy:latest
RUNSECURE_RUNNER_IMAGE_DEFAULT=ghcr.io/andend-collective/runsecure/runner-node:24
RUNSECURE_PAT_FILE=/path/to/your/0400-mode/pat
EOF

# 4. Bring up the scope stack.
docker compose -f infra/orchestrator/compose.scope.yml --env-file infra/orchestrator/scopes/my.env up -d
```

## See also

- `install.md` (top-level) — full user-facing walkthrough including PAT
  provisioning, GitHub repo settings, and troubleshooting.
- `compose.scope.yml` — the per-scope compose definition.
- `scopes/example.yml` — checked-in scope template.
- `.cornerstone/events/runsecure.orchestrator.*.yaml` — emitted event registry.
