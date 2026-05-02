# RunSecure

**Disposable, hardened containers for GitHub Actions self-hosted runners.**
One container per job. No persistent state. All outbound traffic filtered
through an egress proxy you control.

If you run self-hosted GH Actions runners on your own hardware, RunSecure
is the layer between "I need a runner" and "the runner can read my SSH
keys, push to my AWS, and stay alive between jobs."

---

## Why you might want this

Self-hosted runners on bare metal are a shared, persistent environment.
A compromised GitHub Action or a malicious npm dependency can:

- Read SSH keys, cloud credentials, and browser cookies from the host
- Send stolen secrets to an attacker-controlled domain
- Spawn background processes that survive the job finishing
- Reach your internal services and the cloud-provider metadata endpoint
  (`169.254.169.254`)

This isn't theoretical. The
[tj-actions/changed-files supply-chain attack](https://github.com/advisories/GHSA-mrrh-fhqg-pjh4)
in March 2025 did all of those things to every repo that used it.

GitHub-hosted runners avoid this with disposable VMs you don't pay for.
If you've moved to self-hosted runners (cost, GPU access, large memory,
private-network builds, ARM64), you've inherited the security model and
don't have an obvious replacement for the disposability.

RunSecure is that replacement.

---

## What it actually does

Each CI job runs in a fresh container that:

| Hardening | How |
|---|---|
| **Ephemeral** | `--rm`, destroyed the moment the job ends. No state survives. |
| **Non-root** | UID 1001, root account locked, shell set to nologin |
| **No capabilities** | `cap_drop: ALL` (only `NET_BIND_SERVICE` on the proxy) |
| **No privilege escalation** | `no-new-privileges:true`, all setuid bits stripped |
| **Restricted syscalls** | Custom seccomp profile blocks `ptrace`, `mount`, `bpf`, `keyctl`, `swapon`, etc. |
| **Read-only system paths** | `/etc` is `chmod 555`; `/etc/passwd` and `/etc/group` are `444` |
| **No package manager** | `apt`/`dpkg` removed in finalize-hardening; nothing can be installed at runtime |
| **No network recon tools** | `ping`, `nc`, `ssh`, `wget` removed |
| **Egress allowlist** | Network goes through Squid (HTTP/HTTPS) + HAProxy (raw TCP) + dnsmasq (DNS). Anything not on your allowlist is blocked. |
| **Cloud-metadata blocked** | `169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254` all refused |
| **PID-1 reaping** | `init: true` ensures zombie processes don't accumulate |

The egress allowlist is the load-bearing piece. Even if a malicious
package executes inside the runner, it can't talk to anything you didn't
already approve. That's the property tj-actions/changed-files needed
the most and didn't have.

---

## What it explicitly does NOT do

- **Block exfiltration over allowed domains.** If you allow `github.com`,
  an attacker can still create issues, push to repos they control, or
  encode data in commit messages. The mitigation is workflow-level
  (`GITHUB_TOKEN` permissions, branch protection), not network-level.
- **Replace your need to vet third-party Actions.** RunSecure makes
  compromise less catastrophic, not impossible.
- **Solve secrets management.** Workflows that `set -x` or `echo $TOKEN`
  still leak secrets to the per-job log. RunSecure ships logs to GitHub
  via the runner's normal upload — encrypted at rest, but visible to
  anyone with the right repo permissions.
- **Provide multi-job isolation.** One runner = one container = one job.
  Run multiple instances of `run.sh` for parallel jobs.

For the full threat model, see [SECURITY.md](./SECURITY.md).

---

## Prerequisites

- **Docker Engine 20.10+** (or Docker Desktop / Colima — anything with
  `docker compose v2`)
- **`gh` CLI** authenticated against the GitHub repo whose CI you're
  hardening (used to request JIT runner tokens)
- **`yq` v4+** for parsing `runner.yml`
- **Linux or macOS host** with at least 8 GB RAM available (Node CI
  builds eat 4 GB on a busy day; 16 GB recommended on macOS where
  the VM steals memory)

```bash
# macOS
brew install docker colima yq gh
colima start --cpu 4 --memory 16 --vm-type vz --mount-type virtiofs
gh auth login

# Debian/Ubuntu
apt install docker.io gh
# yq: download from https://github.com/mikefarah/yq/releases (apt's yq is the wrong tool)
```

---

## Quick Start

> **Heads-up on versioning.** The latest published release on GHCR is
> `v1.1.1` (April 2026). It pre-dates the TCP-egress, DNS, and Grype-scan
> work merged in PR #24. If you want those, either pin to a newer version
> once it's published (the weekly auto-bump cuts a fresh release every
> Monday 02:30 UTC) **or** clone the repo and run from source as shown
> below.

### Clone-and-run (recommended)

The orchestrator references files across the repo (`docker-compose.yml`,
`squid/Dockerfile`, the `lib/` helpers). It needs the repo on disk.

```bash
git clone https://github.com/AndEnd-Collective/RunSecure.git
cd RunSecure

# Build the base + the language layer you want
docker build -f images/base.Dockerfile -t runner-base:latest .
docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .
# (or python.Dockerfile / rust.Dockerfile)

# Create runner.yml in YOUR project (the repo whose CI you want hardened)
cat > /path/to/your-project/.github/runner.yml <<'YML'
runtime: node:24
http_egress:
  - .npmjs.org
  - .github.com
YML

# Update YOUR project's workflow to require the matching labels
# (in your-project/.github/workflows/ci.yml):
#   runs-on: [self-hosted, Linux, ARM64, container]

# Start a runner (picks up one job, then exits — re-run for the next)
./infra/scripts/run.sh --project /path/to/your-project --repo your-org/your-repo
```

That's it. The orchestrator will:

1. Read your `runner.yml` and validate it (rejects unknown fields)
2. Build a project-specific image layering any tools you specified
3. Start the egress proxy + the runner container on an isolated network
4. Request a JIT runner token from GitHub
5. Run one job, tear everything down

To process more than one job, run with `--max-jobs N` or just call
`run.sh` again. Each invocation is self-contained.

### Architecture mismatch warning

The default `labels:` is `[self-hosted, Linux, ARM64, container]`. If
you're on x86_64 (most non-Mac hardware), your workflow's `runs-on:`
won't match unless you override:

```yaml
# in runner.yml
labels: [self-hosted, Linux, X64, container]

# in your workflow
runs-on: [self-hosted, Linux, X64, container]
```

---

## `runner.yml` — the full schema

Only `runtime:` is required. Everything else has sensible defaults.

```yaml
runtime: node:24                       # Required. node:24, node:22,
                                       # python:3.12, python:3.11,
                                       # rust:stable | beta | nightly | 1.X.Y

http_egress:                           # HTTP/HTTPS allowlist (Squid)
  - .npmjs.org                         # Domain prefix matches all subdomains
  - api.example.com                    # Bare domain matches exact host
  - .pypi.org

tcp_egress:                            # Raw-TCP allowlist (HAProxy)
  - postgres.example.com:5432          # host:port, ports must be unique

dns:                                   # DNS resolver (default: host DNS)
  host: false                          # false = run dnsmasq inside the proxy
  servers: [1.1.1.1]                   # required when host:false
  hosts_file: ./infra/dns/hosts.txt    # optional static map (path or https://)
  whitelist_file: ./allow.txt          # optional strict allowlist (path or https://)
  log_queries: true                    # log to _diag-proxy/dnsmasq.log

apt:                                   # Extra system packages on top of base
  - postgresql-client                  # (lowercase Debian package names only)

tools:                                 # Optional CI-tool layers
  - playwright                         # ~300 MB; needs Node
  - semgrep                            # ~276 MB; auto-installs Python
  - cypress                            # ~250 MB; needs Node

hardening:                             # Optional: prune tools you don't use
  remove: [unzip]                      # rm the binary; calls get "command not found"
  stub: [curl, jq]                     # replace with a friendly stub:
                                       #   $ curl https://example.com
                                       #   [runsecure] 'curl' was intentionally
                                       #   replaced by hardening.stub in your
                                       #   runner.yml. Exits 127.

resources:                             # Container limits
  memory: 8g
  cpus: 4
  pids: 2048

labels: [self-hosted, Linux, ARM64, container]   # Must match runs-on:

version: "1.1.1"                       # Pin a published release (skip for
                                       # local-build mode)
```

Validate any `runner.yml` against the schema:

```bash
./infra/scripts/lib/validate-schema.sh path/to/runner.yml
```

---

## How the egress proxy works

The runner container has **no direct internet route**. Its only network
peer is the proxy container, which sits on two networks: the
runner-only internal network and the host-reachable external bridge.

```
   YOUR JOB                  PROXY CONTAINER             INTERNET
   ┌────────────┐            ┌───────────────────┐       ┌──────────┐
   │  runner    │  HTTP/S    │  Squid :3128      │  ───▶ │ allowed  │
   │  container │ ─────────▶ │   (allowlist)     │       │ domains  │
   │            │            │                   │       └──────────┘
   │  HTTP_PROXY│  raw TCP   │  HAProxy :PORTS   │  ───▶ ┌──────────┐
   │  ─ ─ ─ ─ ─ │ ─────────▶ │   (per-port)      │       │ approved │
   │            │            │                   │       │ host:port│
   │            │  DNS       │  dnsmasq :53      │  ───▶ └──────────┘
   │            │ ─────────▶ │   (optional)      │
   └────────────┘            └───────────────────┘
   internal: true             dual-homed
```

- **Squid** filters HTTP/HTTPS by domain. CONNECT to anything not on
  the allowlist is refused. The runner gets `HTTP_PROXY` set
  automatically.
- **HAProxy** opens a TCP frontend on each `tcp_egress` port. Connecting
  to that port from the runner is forwarded to the configured
  destination only. Other TCP ports have no listener.
- **dnsmasq** (only when `dns.host: false`) runs DNS inside the proxy
  with your servers, optional `hosts_file` overrides, and optional
  `whitelist_file` enforcement.

The proxy is **fail-closed**: if Squid, HAProxy, or dnsmasq dies, the
proxy container exits and the runner's network calls start failing
immediately.

The base allowlist (built into `infra/squid/base.conf`) covers
`github.com`, `*.npmjs.org`, `*.pypi.org`, `crates.io`, `docker.io`,
GHCR, and a few CI-essential tools. Project-specific entries from
`http_egress:` are added on top.

---

## Testing

The full validation suite builds every language image and runs ~35
hardening checks against each (non-root, no setuid, no apt, locked
root, etc.):

```bash
./tests/validation/run-all-tests.sh             # all images
./tests/validation/run-all-tests.sh --quick     # skip Rust (slow)
./tests/validation/run-all-tests.sh --skip-build # reuse cached images
```

Integration tests bring up the proxy + runner stack on an isolated
Docker network and exercise CI workflows end-to-end:

```bash
./tests/integration/run-integration-tests.sh                  # all suites
./tests/integration/run-integration-tests.sh --test egress    # egress allowlist tests
./tests/integration/run-integration-tests.sh --test tcp       # HAProxy TCP egress
./tests/integration/run-integration-tests.sh --test dns       # dnsmasq paths
./tests/integration/run-integration-tests.sh --test attack    # simulated attacks
./tests/integration/run-integration-tests.sh --test node      # Node CI lifecycle
./tests/integration/run-integration-tests.sh --test python    # Python CI lifecycle
```

A separate Grype CVE scan runs in CI on every PR that touches
`images/` or `tools/`. The post-publish workflow re-scans every image
that gets pushed to GHCR — a HIGH/CRITICAL CVE with an upstream fix
blocks the publish.

---

## Self-hosting RunSecure for its own CI

The repo dogfoods its own runner. The `dogfood.yml` workflow runs the
validation and unit lints on a RunSecure-hardened runner, proving the
runtime works for real CI workloads.

To bring it online, run the orchestrator on any Linux host with Docker
(or macOS with Colima):

```bash
git clone https://github.com/AndEnd-Collective/RunSecure.git
cd RunSecure

# Pick up dogfood.yml jobs as they queue — runs forever, one job per cycle
./infra/scripts/run.sh \
    --project . \
    --repo AndEnd-Collective/RunSecure \
    --max-jobs 100
```

The repo-root `.github/runner.yml` defines what the self-hosted runner
should look like (Node 24 base, minimal allowlist for `github.com` + PyPI,
ARM64 labels). When no orchestrator is running, `dogfood.yml`'s jobs
queue silently without blocking the rest of CI (`smoke-test`, `validate`,
`grype-scan` all run on `ubuntu-latest`).

**Why `dogfood.yml` doesn't run integration tests**: integration tests
spawn nested Docker (`docker-compose` brings up the proxy + a second
runner). Inside a hardened RunSecure container with `cap_drop: ALL` +
seccomp, that's intentionally blocked — it's the security property the
project is built around. The full integration suite continues to run on
`ubuntu-latest` via `smoke-test.yml`.

## Pre-push lint hook

A pre-push hook in `.githooks/pre-push` runs the same lints CI runs,
catching regressions before they leave your laptop. One-time setup:

```bash
./.githooks/install
```

Now `git push` runs all 11 lint files (~30s) and refuses to push on any
failure. To bypass in an emergency: `git push --no-verify`.

---

## Operational notes

### Per-job logs land on the host

The runner's `_diag/` directory (the actions-runner's per-job worker
log) is bind-mounted to the orchestrator's working directory. When a
job crashes before logs upload, you still have `_diag/Worker_*.log`
locally for triage. One generation of rotation is kept in
`_diag.previous/`.

To turn this off (e.g. shared CI hosts where multiple users access the
disk):

```bash
RUNSECURE_DIAG_RETENTION=0 ./infra/scripts/run.sh ...
```

The synchronous log-upload-wait still ensures `gh api .../jobs/<id>/logs`
returns the actual log instead of `BlobNotFound`.

### JIT token exposure

The orchestrator passes the GitHub JIT runner token to the container
via the `RUNNER_JIT_CONFIG` environment variable. The entrypoint reads
it once and `unset`s it, but it's briefly visible to `docker inspect`
and to processes inside the container that read `/proc/1/environ`.

If you're running on a shared host where unprivileged users could
inspect container state, set `RUNNER_JIT_CONFIG_FILE` instead — the
entrypoint reads it from a tmpfs file and removes the file after
reading. The orchestrator-side switch to file-mode is tracked as a
follow-up; see [SECURITY.md §14](./SECURITY.md#known-limitations).

### Updating

Releases follow weekly cadence. Every Monday at 02:30 UTC, the
weekly-version-bump workflow tags `vX.Y.(Z+1)` and the publish workflow
rebuilds every image with `--no-cache: true` (so Debian package security
updates land), runs Grype, and pushes to GHCR.

To consume a release as a project:

```yaml
# in runner.yml
version: "1.1.2"
runtime: node:24
```

To trigger a manual release:

```bash
gh workflow run weekly-version-bump.yml -f bump_type=patch  # or minor / major
```

---

## Project layout

```
images/                  # Dockerfiles for base + language layers
infra/
  docker-compose.yml     # Runner + proxy stack
  scripts/
    run.sh               # Orchestrator (entry point — call this)
    compose-image.sh     # Builds the project-specific image
    generate-egress-conf.sh # Generates squid/haproxy/dnsmasq configs
    entrypoint.sh        # Runs inside the container; starts the runner
    finalize-hardening.sh # Strips apt, locks /etc, applies hardening:
    lib/                 # Shared helpers (schema validator, fetcher, etc.)
  squid/                 # Proxy image — squid + haproxy + dnsmasq + supervisor
  seccomp/               # Custom seccomp profile (node-runner.json)
tools/                   # Optional layers (cypress.sh, playwright.sh, ...)
tests/
  validation/            # Per-image hardening tests (no Docker network)
  integration/           # End-to-end with proxy + runner + simulated attacks
SECURITY.md              # Threat model + known limitations
.grype.yaml              # CVE allowlist (vendored-runner GHSAs only)
.github/workflows/       # CI: build, scan, publish, weekly-bump
```

---

## Contributing

Bug reports and PRs welcome. The integration test suite must pass
locally before opening a PR (`./tests/integration/run-integration-tests.sh`).
Adding a new tool? See `tools/cypress.sh` as the canonical template:
pin the version, install + chown caches, end with cleanup.

License: see [LICENSE](./LICENSE).
