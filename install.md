# Installing the RunSecure Orchestrator (Compose backend)

This guide walks through standing up the long-running orchestrator using
the Compose backend. The orchestrator polls GitHub for queued workflow
jobs and spawns ephemeral hardened runner containers on demand —
coexisting with `infra/scripts/run.sh` and
`infra/scripts/dev/bootstrap-self-runner.sh`, which remain first-class
one-shot paths.

For the design rationale, see
`docs/superpowers/specs/2026-05-19-persistent-local-runners-design.md`
(local-only; not committed).

---

## 1. Decide your deployment target

- **Compose backend** (this guide) — runs on Colima or Docker Desktop, one
  Compose stack per scope. Set `backend: compose` in the scope config.
- **Kubernetes backend** — Helm-based deployment to an existing cluster.
  See [`install-kubernetes.md`](install-kubernetes.md). Set `backend: kube`
  in the scope config. Requires a NetworkPolicy-enforcing CNI (Calico or
  Cilium); kindnet/flannel do not enforce NetworkPolicy.

---

## 2. Provision a fine-grained Personal Access Token (PAT)

The orchestrator needs a GitHub PAT scoped to **just the repos in your
scope** with these permissions (and nothing else):

| Permission | Why it's required |
|---|---|
| **Administration: Read & Write** | `POST /repos/{repo}/actions/runners/generate-jitconfig` (every spawn) and `DELETE /repos/{repo}/actions/runners/{id}` (A1 leak cleanup) require this — there is no API path that avoids it. |
| **Actions: Read** | `GET /repos/{repo}/actions/runs?status=queued` (the poll endpoint). |
| **Metadata: Read** | Auto-included for any fine-grained PAT; not optional. |

Create the token at <https://github.com/settings/tokens?type=beta>:

1. Click *Generate new token → Fine-grained personal access token*.
2. **Repository access:** *Only select repositories* — list exactly the
   repos you want the orchestrator to serve.
3. **Repository permissions:** set the three above. Leave everything else
   as *No access*.
4. Set the expiration to ≤ 90 days (the spec accepts up to 1 year; tighter
   is better).
5. Generate, copy the token value into a local file:
   ```sh
   umask 077
   mkdir -p ~/.config/runsecure
   echo 'github_pat_XXXX...' > ~/.config/runsecure/datacentric.pat
   chmod 0400 ~/.config/runsecure/datacentric.pat
   ```
   The orchestrator **refuses to start** if the PAT file is not mode 0400.

---

## 3. Enable self-hosted runners in each target repo

This is a one-time per-repo task, **distinct** from the App permission
above:

1. Open your repo's *Settings → Actions → Runners*.
2. Toggle *Allow self-hosted runners*.
3. (No need to register a static runner — the orchestrator's JIT path
   does that on every spawn.)

If you skip this, the `generate-jitconfig` API call returns a 422; the
orchestrator's circuit breaker (B4) will open after 5 consecutive failures
and stop polling that repo until you fix the toggle.

---

## 4. Pick a security preset

A scope's `security_profile` field sets the default behavior of the
proxy stack. Project `runner.yml` files can override individual knobs
within the bounds set by `allow_project_overrides`. The structural floor
— runner has no path that bypasses the proxy, proxy allowlist not
writable from runner, no raw sockets / `NET_ADMIN`, no kube-SA — is
non-negotiable and the same under every preset.

| Knob | strict (default) | standard | permissive |
|---|---|---|---|
| Wildcards in egress allowlist (`*.foo.com`) | denied | allowed | allowed |
| DoH providers (`cloudflare-dns.com`, `dns.google`) | denied | denied | allowed if listed |
| Cloud IMDS endpoint (169.254.169.254) | denied | denied | allowed if listed |
| `kube-apiserver` reachable from runner Pods (k8s only) | denied | denied | allowed if listed |
| Service-mesh sidecar auto-inject (k8s only) | disabled | disabled | inherit cluster default |
| DNS suffix-match for `*.foo.com` entries | exact only | suffix allowed | suffix allowed |

**Any explicit user listing always wins** — e.g. a project's
`runner.yml` that lists `*.amazonaws.com` under `security_overrides.allow_wildcards`
will be honoured even if the scope is `strict`, *provided the scope's
`allow_project_overrides` includes `allow_wildcards`*.

Recommended starting point: `strict`, plus `allow_project_overrides:
[allow_wildcards]` so individual repos can opt into specific wildcard
domains as needed.

---

## 5. Create the scope config

Keep the rendered scope outside the RunSecure checkout so repository cleanup,
branch switches, and fresh clones cannot remove operator state:

```sh
mkdir -p "$HOME/.config/runsecure"
cp infra/orchestrator/scopes/example.yml \
  "$HOME/.config/runsecure/datacentric.scope.yml"
```

Edit `$HOME/.config/runsecure/datacentric.scope.yml`:

```yaml
apiVersion: runsecure.io/v1alpha1
name: datacentric
description: Datacentric repo runners.
global_max_runners: 5
poll_interval_seconds: 15
security_profile: strict
allow_project_overrides:
  - allow_wildcards
auth:
  type: pat
  pat_file: /run/secrets/runsecure-pat
orch_egress:
  allow_domains:
    - api.github.com
repos:
  - repo: NaorPenso/datacentric
    project_dir: /projects/datacentric
    max_concurrent: 3
```

Create an external `.env` file that points the Compose stack at the scope,
local images, PAT file, and project workspace. It contains paths, never the PAT
value itself:

```sh
cat > "$HOME/.config/runsecure/datacentric.env" <<EOF
RUNSECURE_SCOPE=datacentric
RUNSECURE_SCOPE_FILE_HOST=$HOME/.config/runsecure/datacentric.scope.yml
RUNSECURE_SOCKET_PROXY_IMAGE=runsecure-socket-proxy:local
RUNSECURE_ORCHESTRATOR_IMAGE=runsecure-orchestrator:local
RUNSECURE_PROXY_IMAGE=ghcr.io/andend-collective/runsecure/proxy:latest
RUNSECURE_RUNNER_IMAGE_DEFAULT=ghcr.io/andend-collective/runsecure/node:latest-24
RUNSECURE_PAT_FILE=$HOME/.config/runsecure/datacentric.pat
RUNSECURE_PROJECTS_ROOT=$HOME/Code/Naor
EOF
```

`RUNSECURE_PROJECTS_ROOT` is the *parent* directory holding every repo
checkout this scope will serve — `compose.scope.yml` mounts it once,
read-only, at `/projects` inside the orchestrator container. Both it and
`RUNSECURE_SCOPE_FILE_HOST` are required; Compose fails during configuration
if either is absent. Each repo's `project_dir` in the scope YAML must then
point at the matching subdirectory, e.g. a checkout at
`$RUNSECURE_PROJECTS_ROOT/datacentric` is `project_dir: /projects/datacentric`.

This means `infra/orchestrator/compose.scope.yml` never needs hand-editing
per repo or per operator — the tracked file stays untouched, and everything
operator- or project-specific lives in the gitignored `.env` file and scope
YAML instead.

### Choosing runner images (and bringing your own)

Each project's `.github/runner.yml` `runtime:` field selects which runner
image the orchestrator spawns. The orchestrator resolves it from an env var
in your scope `.env` file:

- `runtime: node` → `RUNSECURE_RUNNER_IMAGE_NODE`
- `runtime: python` → `RUNSECURE_RUNNER_IMAGE_PYTHON`
- `runtime: rust` → `RUNSECURE_RUNNER_IMAGE_RUST`
- anything else / unset → `RUNSECURE_RUNNER_IMAGE_DEFAULT`

Point any of these at a **custom runner image** (your own registry digest)
and it works on both backends with no code changes — the orchestrator
applies the identical hardening to whatever image you name. Two requirements:

1. **Allowlist it.** The socket-proxy only lets the daemon create containers
   from digests in its allowlist. Released RunSecure images are baked into the
   same release's socket-proxy from immutable build outputs. For a custom
   image, point `RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE_HOST` at a local file
   containing its `@sha256:…` reference (see Troubleshooting).
2. **Satisfy the runner-image contract.** Your image MUST ship:
   - the GitHub Actions runner at `/home/runner/actions-runner`, and
   - RunSecure's JIT launcher at `/home/runner/entrypoint.sh`
     (the orchestrator pins the runner's entrypoint/command to this path on
     both backends, so it must exist and be executable by UID 1001).

   **Easiest path — don't hand-roll an image.** Add your extra tools via the
   project's `runner.yml` `tools:` block instead. `compose-image.sh` layers
   them onto a RunSecure base image *before* finalize-hardening, so the
   result inherits the runner binary, the baked entrypoint, and every
   hardening property automatically. Only reach for a fully custom image ref
   when the `tools:` block genuinely can't express what you need — and if you
   do, the cleanest way to meet the contract is to build `FROM` your own base
   and `COPY infra/scripts/entrypoint.sh /home/runner/entrypoint.sh` yourself.

---

## 6. Bring up the stack

Build local images (or pull from GHCR when published):

```sh
docker build -t runsecure-socket-proxy:local infra/socket-proxy
docker build -t runsecure-orchestrator:local  infra/orchestrator
```

Launch the scope:

```sh
docker compose \
  -f infra/orchestrator/compose.scope.yml \
  --env-file "$HOME/.config/runsecure/datacentric.env" \
  up -d
```

Three containers come up:

- `rs-orch-datacentric-socket-proxy` — the **only** thing mounting
  `/var/run/docker.sock` (read-only).
- `rs-orch-datacentric-egress` — the orchestrator's outbound HTTP proxy
  (allowlist defaults to `api.github.com` only).
- `rs-orch-datacentric` — the orchestrator itself (distroless, nonroot,
  RO rootfs, `cap_drop: ALL`).

---

## 7. Verify

The orchestrator exposes `/healthz` and `/metrics` on localhost ports
(never published externally):

```sh
curl -sf http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl -sf http://127.0.0.1:8081/metrics | head -20
# runsecure_orchestrator_in_flight_runners{repo="..."} 0
# runsecure_orchestrator_queued_jobs{repo="..."} 0
# ...

curl -sf http://127.0.0.1:8081/state/snapshot | jq .
# { "per_repo": {...}, "global_in_flight": 0, "rate_limit_remaining": ... }
```

Watch live event traffic:

```sh
docker logs -f rs-orch-datacentric | jq -c 'select(.["event.sub.type"]?)'
```

Trigger a spawn by pushing a workflow that targets one of the runner
labels in your `runner.yml` (`self-hosted`, `Linux`, `container`). You
should see, in order:

```
runsecure.orchestrator.poll.tick
runsecure.orchestrator.poll.queued_jobs_observed
runsecure.orchestrator.spawn.started
runsecure.orchestrator.spawn.jit_acquired
runsecure.orchestrator.spawn.runner_created
runsecure.orchestrator.spawn.completed
```

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Orchestrator exits with `auth.pat_file ... mode 0400` | PAT file has wrong perms | `chmod 0400 <pat>` |
| `auth.pat_file ... no such file` | Bind-mount in compose.scope.yml is wrong | Verify `RUNSECURE_PAT_FILE` in .env points at the real file |
| Many `runsecure.orchestrator.auth.degraded` events | PAT lacks Administration:RW for one or more listed repos | Re-issue with correct permissions; the orchestrator reloads on PAT-file mtime change |
| Many `socket_proxy_denied` in `spawn.failed` events | Runner image digest is absent from the baked release allowlist and optional operator allowlist | Verify the runner and socket-proxy came from the same release. For a custom image, set `RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE_HOST` in the scope `.env` file to a local file listing the extra digest(s) (same format as `allowed-images.txt`) — `compose.scope.yml` mounts it automatically, with no tracked-file edit. |
| Breaker stuck open (no spawns) | 5 consecutive spawn failures | `docker logs rs-orch-* \| grep breaker.opened` — fix the upstream cause; the breaker enters half-open after 5min cooldown |
| Lots of `ratelimit.paused` events | GitHub API quota exhausted (rare at 15s polling) | Increase `poll_interval_seconds` or reduce scope size |
| Runner containers accumulate (`docker ps` shows many) | Orchestrator died mid-flight without graceful drain | Restart it; A4 cold-start reconciliation re-counts in-flight; orphan proxy containers are torn down on the same path |

---

## 9. Coexistence with `run.sh`

`infra/scripts/run.sh` and `infra/scripts/dev/bootstrap-self-runner.sh`
**continue to work unchanged**. They use a disjoint container naming
prefix (`rs-<repo>-jobN`) from the orchestrator (`rs-<repo>-<spawn-id>`),
so the two paths can run simultaneously against the same repo.

If you want to migrate fully off the manual path, the orchestrator covers
every use-case `run.sh` supports for queued workflows. Keep `run.sh` for:

- Pre-warming images interactively (`--force` flag).
- One-shot diagnostic runs that should NOT compete for the orchestrator's
  concurrency slots.
- `bootstrap-self-runner.sh` for the self-CI loop on this very repo.

---

## 10. Uninstall

Stop and remove the stack:

```sh
docker compose -f infra/orchestrator/compose.scope.yml \
  --env-file "$HOME/.config/runsecure/datacentric.env" \
  down --volumes --remove-orphans
```

If you have orphan GitHub-side runner registrations (rare; A1 leak
cleanup handles most cases), remove them with:

```sh
gh api -X DELETE "/repos/NaorPenso/datacentric/actions/runners/<id>"
```

Delete the local PAT file:

```sh
rm ~/.config/runsecure/datacentric.pat
rm ~/.config/runsecure/datacentric.scope.yml \
   ~/.config/runsecure/datacentric.env
```

Revoke the PAT on GitHub for completeness.
