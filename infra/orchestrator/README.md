# RunSecure Orchestrator (Compose backend)

Distroless Go binary that polls GitHub for queued workflow runs and spawns
ephemeral hardened runner containers (or Pods) on demand via a custom Go
docker-socket-proxy (Compose backend) or Kubernetes client (Kubernetes
backend). For the full design see
`docs/superpowers/specs/2026-05-19-persistent-local-runners-design.md`.

## Quickstart

Requires Docker with Compose v2, Python 3, `jq`, and an authenticated GitHub CLI
(`gh`).

```sh
# 1. Keep operator state outside the checkout.
mkdir -p "$HOME/.config/runsecure"
cp infra/orchestrator/scopes/example.yml "$HOME/.config/runsecure/my.scope.yml"
# Edit my.scope.yml so each project_dir is below /projects.

# 2. Resolve every image from one promoted release's immutable manifest.
RUNSECURE_RELEASE=2.1.8
RUNSECURE_RELEASE_MANIFEST="$HOME/.config/runsecure/runsecure-v${RUNSECURE_RELEASE}-release-images.json"
gh release download "v${RUNSECURE_RELEASE}" \
  --repo AndEnd-Collective/RunSecure \
  --pattern "runsecure-v${RUNSECURE_RELEASE}-release-images.json" \
  --dir "$HOME/.config/runsecure" \
  --clobber
python3 infra/scripts/verify-release-manifest.py \
  "$RUNSECURE_RELEASE_MANIFEST" --expected-release "$RUNSECURE_RELEASE"
SOCKET_PROXY_REF=$(jq -er '.images["socket-proxy"]' "$RUNSECURE_RELEASE_MANIFEST")
ORCHESTRATOR_REF=$(jq -er '.images["orchestrator"]' "$RUNSECURE_RELEASE_MANIFEST")
PROXY_REF=$(jq -er '.images["proxy"]' "$RUNSECURE_RELEASE_MANIFEST")
RUNNER_REF=$(jq -er '.images["node-24"]' "$RUNSECURE_RELEASE_MANIFEST")

# 3. Create a per-scope .env (paths and exact refs; never put the PAT value here).
cat > "$HOME/.config/runsecure/my.env" <<EOF
RUNSECURE_SCOPE=my
RUNSECURE_SCOPE_FILE_HOST=$HOME/.config/runsecure/my.scope.yml
RUNSECURE_SOCKET_PROXY_IMAGE=$SOCKET_PROXY_REF
RUNSECURE_ORCHESTRATOR_IMAGE=$ORCHESTRATOR_REF
RUNSECURE_PROXY_IMAGE=$PROXY_REF
RUNSECURE_RUNNER_IMAGE_DEFAULT=$RUNNER_REF
RUNSECURE_PAT_FILE=/path/to/your/0400-mode/pat
RUNSECURE_PROJECTS_ROOT=/path/to/parent/of/project/checkouts
# Optional host ports; keep distinct when running multiple scope stacks.
RUNSECURE_ORCHESTRATOR_HEALTH_PORT=8080
RUNSECURE_ORCHESTRATOR_STATE_PORT=8081
EOF

# 4. Bring up the scope stack through the host PAT preflight.
infra/scripts/orchestrator-compose.sh \
  --env-file "$HOME/.config/runsecure/my.env" up -d
```

The wrapper uses `os.lstat` on the exact bind source rendered by Compose and
requires a regular, non-symlink file owned by the invoking UID at mode `0400`.
The tracked Compose file requires the wrapper's validation sentinel, so an
accidental raw `docker compose up` fails before creating services. Use the same
wrapper for `down`, `logs`, and other Compose commands.

The socket-proxy image is intentionally from the same release: its baked
allowlist contains these exact proxy and runner digests. Do not mix release
manifests. For a custom image only, point
`RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE_HOST` at a local digest allowlist.

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
