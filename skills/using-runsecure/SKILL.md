---
name: using-runsecure
description: Use when adopting RunSecure to harden a project's GitHub Actions CI — set up hardened, ephemeral, egress-controlled self-hosted runners. Triggers when a user wants secure/sandboxed CI runners, egress allowlisting for CI, to run untrusted workflow code safely, or asks to "set up / configure / adopt RunSecure" for a repo.
---

# Using RunSecure

RunSecure runs each GitHub Actions job in a **hardened, ephemeral Docker container** (non-root, setuid stripped, apt removed, read-only `/etc`, seccomp, `cap_drop ALL`) whose **only** network path is a proxy that enforces a **default-deny, allowlist-only** egress policy from the project's `runner.yml`. One job per container, then destroyed.

This skill guides adopting RunSecure in a target project. RunSecure itself is a separate repo (clone it); the project you are hardening only needs a `.github/runner.yml` and matching workflow labels.

## Mental model (do not violate)

- **Images are terminal.** Never `FROM ghcr.io/andend-collective/runsecure/*` to layer tools on top — the hardening is final. Extra tools go through `runner.yml` (`tools:` / `apt:`), applied *before* `finalize-hardening.sh`.
- **Egress is whitelist-only.** If a build needs to reach a host, it must be in `runner.yml` (`http_egress` for HTTP/HTTPS domains, `tcp_egress` for raw TCP `host:port`). Default-deny otherwise. Literal private/special-range IPs are rejected unless the operator opts the range in (`orchestrator.security_overrides.allow_private_cidrs`, gated by scope).
- **One job per runner**, then exit. Never reuse a runner across jobs.

## Adoption workflow

### 1. Author `.github/runner.yml` in the target project

Only `runtime:` is required. Full 2.0.0 schema (see RunSecure `README.md` § "`runner.yml` — the full schema" and `skeleton/runner.yml`):

```yaml
runtime: node:24                     # node:24 | node:22 | python:3.12 | rust:stable
labels: [self-hosted, Linux, ARM64, container]   # must match workflow runs-on

# OPTIONAL CI tools baked into the image (installed before hardening)
tools: [playwright, semgrep, cypress]
apt:   [libvips-dev]                 # extra system packages

# EGRESS — default-deny; list everything the build legitimately needs.
http_egress:                         # HTTP/HTTPS domains (squid). ".x.com" = subdomains
  - .npmjs.org
  - api.github.com
tcp_egress:                          # raw TCP host:port (haproxy). Unique ports; not 80/443.
  - ep-foo.neon.tech:5432
dns:                                 # optional; isolated dnsmasq when host: false
  host: false
  servers: [10.0.0.53]

resources: { memory: 8g, cpus: 4, pids: 2048 }
```

- `http_egress` replaces the deprecated `egress.allow_domains` (still aliased + WARNs in 2.x, removed in 3.0). Use `http_egress`.
- Each `tcp_egress` port must be unique and not 80/443 (use `http_egress` for those). The workflow/app connects to `proxy:<port>`.
- Validate before running: `bash infra/scripts/lib/validate-schema.sh <project>/.github/runner.yml`.

### 2. Point the project's workflow at the runner labels

In the target repo's `.github/workflows/*.yml`, set `runs-on` to **exactly** the `labels` from `runner.yml`:

```yaml
jobs:
  build:
    runs-on: [self-hosted, Linux, ARM64, container]
```

### 3. Build the images (from the RunSecure repo)

```bash
docker build -f images/base.Dockerfile -t runner-base:latest .
docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .
# or compose a project-specific image (layers runner.yml tools + finalize-hardening):
./infra/scripts/compose-image.sh /path/to/project
```

Or pin to a published release in `runner.yml` (`version: "2.0.0"`) to pull from GHCR instead of building.

### 4. Run a runner

- **One job, on demand** (simplest): `./infra/scripts/run.sh --project /path/to/project --repo owner/repo`. Add `--no-proxy` only for debugging. Requires Docker, authenticated `gh`, and `yq` v4+.
- **Persistent pool** (Plan A orchestrator, Compose backend): configure an `infra/orchestrator/scopes/<scope>.yml` (scheduler/concurrency + `orch_egress`) and launch the orchestrator stack. The orchestrator delivers per-spawn egress configs to a combined proxy via a shared named volume and keeps the runner egress-isolated.
- **RunSecure's own CI** (dogfood): `./infra/scripts/dev/bootstrap-self-runner.sh` drains queued `dogfood` jobs then exits (no permanent daemon).

### 5. Verify

- Trigger a workflow run; confirm the job is picked up by the labeled runner and the container is destroyed after.
- Egress: an allowed `http_egress`/`tcp_egress` target succeeds; anything else is blocked. Security claims + per-claim acceptance checks are in RunSecure `SECURITY.md`; the published-image acceptance suite is `tests/acceptance/`.

## Common tasks

- **Allow a new domain/host:** add to `http_egress` (domain) or `tcp_egress` (`host:port`), rebuild/republish. Don't disable the proxy.
- **Add a tool:** add to `tools:` (if a recipe exists in `tools/*.sh`) or `apt:`; never layer on top of a published image.
- **Reach a private/internal DB:** the host must resolve to a non-private IP, OR the operator must opt the CIDR in at scope level (`security_overrides.allow_private_cidrs`) — a project cannot self-authorize SSRF to private ranges.

## When NOT to use RunSecure
- GitHub-hosted runners are fine for fully-trusted workflows with no egress-control needs.
- Non-Docker / non-Linux job requirements (RunSecure runs jobs in Linux containers).

For depth: RunSecure `README.md` (consumption, egress proxy, lifecycle), `SECURITY.md` (claims), `AGENTS.md` (operating principles / anti-patterns).
