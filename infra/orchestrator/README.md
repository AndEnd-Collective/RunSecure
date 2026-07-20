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

# 2. Keep operator state outside the checkout.
mkdir -p "$HOME/.config/runsecure"
cp infra/orchestrator/scopes/example.yml "$HOME/.config/runsecure/my.scope.yml"
# Edit my.scope.yml so each project_dir is below /projects.

# 3. Create a per-scope .env (paths only; never put the PAT value here).
cat > "$HOME/.config/runsecure/my.env" <<EOF
RUNSECURE_SCOPE=my
RUNSECURE_SCOPE_FILE_HOST=$HOME/.config/runsecure/my.scope.yml
RUNSECURE_SOCKET_PROXY_IMAGE=runsecure-socket-proxy:local
RUNSECURE_ORCHESTRATOR_IMAGE=runsecure-orchestrator:local
RUNSECURE_PROXY_IMAGE=ghcr.io/andend-collective/runsecure/proxy:latest
RUNSECURE_RUNNER_IMAGE_DEFAULT=ghcr.io/andend-collective/runsecure/node:latest-24
RUNSECURE_PAT_FILE=/path/to/your/0400-mode/pat
RUNSECURE_PROJECTS_ROOT=/path/to/parent/of/project/checkouts
# Optional host ports; keep distinct when running multiple scope stacks.
RUNSECURE_ORCHESTRATOR_HEALTH_PORT=8080
RUNSECURE_ORCHESTRATOR_STATE_PORT=8081
EOF

# 4. Bring up the scope stack.
docker compose -f infra/orchestrator/compose.scope.yml --env-file "$HOME/.config/runsecure/my.env" up -d
```

Health, readiness, metrics, and state reach the host through an unprivileged
relay bound only to `127.0.0.1`. The PAT-holding orchestrator remains attached
exclusively to Docker-internal networks; changing the optional published ports
does not make the bind address configurable.

## See also

- `install.md` (top-level) — full user-facing walkthrough including PAT
  provisioning, GitHub repo settings, and troubleshooting.
- `compose.scope.yml` — the per-scope compose definition.
- `scopes/example.yml` — checked-in scope template.
- `.cornerstone/events/runsecure.orchestrator.*.yaml` — emitted event registry.
