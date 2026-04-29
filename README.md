# RunSecure

Hardened, ephemeral Docker containers for GitHub Actions self-hosted runners — with network egress control.

Each CI job runs in its own disposable container. When the job finishes, the container is destroyed. Nothing persists between jobs. All outbound network traffic is filtered through a proxy that only allows domains you explicitly approve.

---

## The Problem

Bare-metal self-hosted runners are a shared, persistent environment. A compromised GitHub Action or malicious npm package can:

- Read SSH keys, cloud credentials, and browser cookies from the host filesystem
- Send stolen secrets to an attacker-controlled server
- Spawn background processes that survive after the job ends
- Reach internal services and cloud metadata endpoints over the host network

These are not theoretical risks. The [tj-actions/changed-files supply chain attack](https://github.com/advisories/GHSA-mrrh-fhqg-pjh4) (March 2025) demonstrated exactly this — a popular Action was compromised to exfiltrate secrets from every repository that used it.

## How RunSecure Fixes This

**Ephemeral containers** — every job gets a fresh container, destroyed on completion. No persistent state, no leftover processes.

**Network egress proxy** — outbound connections are routed through a Squid proxy with a domain allowlist. Your CI can reach GitHub and your package registry. Everything else is blocked — including attacker-controlled servers, cloud metadata endpoints, and tunneling services.

**Image hardening** — containers run as a non-root user with all Linux capabilities dropped, setuid binaries stripped, dangerous utilities removed, and a custom seccomp profile blocking syscalls like `ptrace`, `mount`, and `bpf`.

**Stackable by design** — you choose a language runtime and that's it. Tools like Playwright, Semgrep, or Cypress can be layered on top if you need them, but nothing beyond the runtime is required. A simple `runtime: node:24` gives you a fully hardened runner ready to go.

---

## Prerequisites

You need Docker, the GitHub CLI, and yq (a YAML processor):

```bash
# macOS
brew install docker colima yq

# Start Colima with enough resources
# 16 GB RAM minimum — large Node projects (npm ci + vitest + next build) need it
colima start --cpu 4 --memory 16 --vm-type vz --mount-type virtiofs

# Verify
docker info | grep "Total Memory"   # Should show 15+ GiB
yq --version                        # Needs yq v4+
gh auth status                      # Must be authenticated
```

---

## Getting Started

### Step 1 — Build the Base Image

Every language image depends on this. Build it first:

```bash
cd /path/to/RunSecure

docker build -f images/base.Dockerfile -t runner-base:latest .
```

This creates a Debian slim image (~320 MB) with the GitHub Actions runner binary, git, curl, jq, and the gh CLI — hardened with a non-root user (UID 1001), all setuid bits stripped, and dangerous utilities removed.

### Step 2 — Build a Language Image

Pick the language your project uses:

```bash
# Node.js 24
docker build -f images/node.Dockerfile \
  --build-arg NODE_VERSION=24 -t runner-node:24 .

# Node.js 22
docker build -f images/node.Dockerfile \
  --build-arg NODE_VERSION=22 -t runner-node:22 .

# Python 3.12
docker build -f images/python.Dockerfile \
  --build-arg PYTHON_VERSION=3.12 -t runner-python:3.12 .

# Rust stable
docker build -f images/rust.Dockerfile \
  --build-arg RUST_VERSION=stable -t runner-rust:stable .
```

Each language image adds the runtime on top of the base image. You can build multiple languages — they share the same base layer via Docker's layer cache.

### Step 3 — Configure Your Project

Create a `.github/runner.yml` file in your project. The only required field is `runtime`:

```yaml
runtime: node:24
```

That's it. This gives you a hardened Node.js 24 runner with the default egress allowlist (GitHub + npm), default resource limits (8 GB RAM, 4 CPUs, 2048 PIDs), and default labels.

For a copy-paste starting point with all options commented out, copy the template:

```bash
cp /path/to/RunSecure/skeleton/runner.yml /path/to/your-project/.github/runner.yml
```

### Step 4 — Update Your GitHub Workflow

Change `runs-on` to use the RunSecure labels:

```yaml
# Before
runs-on: ubuntu-latest
# or
runs-on: [self-hosted, macOS, ARM64]

# After
runs-on: [self-hosted, Linux, ARM64, container]
```

You can remove `setup-node` / `setup-python` steps — the runtime is already baked into the image. Leaving them in is harmless; they'll detect the pre-installed version and skip the download.

An example workflow is provided at `skeleton/workflow-ci.yml`.

### Step 5 — Start the Runner

```bash
./infra/scripts/run.sh \
  --project /path/to/your-project \
  --repo owner/repo-name
```

The orchestrator will:
1. Read your project's `.github/runner.yml` and validate its schema
2. Build or reuse a cached image matching your config
3. Generate all proxy configuration (Squid HTTP allowlist, HAProxy TCP config if needed, dnsmasq DNS config if needed)
4. Request a JIT (Just-In-Time) token from the GitHub API
5. Launch the runner container with full hardening
6. Wait for the job to complete, then destroy the container
7. Repeat for the next queued job

---

## Configuration Reference

All configuration lives in your project's `.github/runner.yml`. Only `runtime` is required — everything else has defaults.

### `runtime` (required)

The language and version for your runner image.

```yaml
runtime: node:24          # Node.js 24 (via NodeSource)
runtime: node:22          # Node.js 22
runtime: python:3.12      # Python 3.12 (Debian packages)
runtime: rust:stable       # Rust stable (via rustup)
```

### `tools` (optional)

Most projects don't need this. The language runtime alone is enough for building, testing, and linting. Only add tools if your CI workflow specifically requires them (e.g., you run Playwright browser tests or Semgrep security scans as part of CI).

Available tools:

```yaml
tools:
  - playwright     # Playwright + Chromium (~300 MB, requires Node.js)
  - semgrep        # Semgrep SAST (~276 MB, auto-installs Python if missing)
  - cypress        # Cypress E2E (~250 MB, requires Node.js)
```

Pick only what you need — each tool adds to your image size. You can also [create your own tool recipes](#adding-a-new-tool-recipe).

When tools are specified, RunSecure generates a project-specific image with a content-hash tag. If two projects share the same runtime + tools combination, they share the same cached image.

### `apt`

Extra system packages to install via apt:

```yaml
apt:
  - libvips-dev
  - ffmpeg
```

These are installed before tools and before final hardening (which removes apt from the image).

### `http_egress`

Additional HTTP/HTTPS domains to allow through the egress proxy, on top of the base allowlist. Use `.domain.com` syntax to allow all subdomains:

```yaml
http_egress:
  - ".neon.tech"           # Neon Postgres (HTTPS API)
  - "api.vercel.com"       # Vercel API (exact domain)
  - ".supabase.co"         # Supabase
  - ".amazonaws.com"       # AWS services
  - ".azure.com"           # Azure services
  - ".sentry.io"           # Sentry error reporting
```

The old key `egress:` still works and is treated identically — use `http_egress:` for new configs.

If you're not sure what domains your CI needs, start without an `http_egress` list. When a step fails due to a blocked connection, check the Squid proxy log for the denied domain and add it.

### `tcp_egress`

Raw TCP connections for database clients, cache servers, or any protocol that does not use HTTP. Each entry is `host:port`. Each port must be unique across all entries.

```yaml
tcp_egress:
  - ep-foo.neon.tech:5432      # Neon Postgres (direct TCP)
  - redis.example.com:6379     # Redis
```

How it works: the orchestrator configures an HAProxy instance inside the proxy container. Each `host:port` entry creates an HAProxy frontend that listens on that port and forwards TCP connections to the target. The runner reaches the target via `proxy:<port>`.

Ports 80 and 443 are reserved for HTTP/HTTPS — use `http_egress` instead.

### `dns`

Controls DNS resolution inside the runner. By default (absent or `host: true`), the runner uses the Docker host's resolver. Setting `host: false` starts an isolated dnsmasq instance inside the proxy container — this prevents DNS-based leakage to the host resolver.

```yaml
dns:
  host: false
  servers:
    - 10.0.0.53               # Private DNS server IP address
  hosts_file: ./infra/dns/hosts.txt   # Optional: local path or https:// URL
  whitelist_file: https://internal.company.com/allowed.txt  # Optional
  log_queries: true           # Default: true when host:false
```

When `host: false`, at least one of `servers` or `hosts_file` is required.

The `hosts_file` and `whitelist_file` values accept either a local filesystem path or an `https://` URL. SSRF protection is applied: private/RFC1918/loopback/CGNAT/IPv6-ULA addresses are blocked before any download attempt.

### `labels`

GitHub runner labels. Your workflow's `runs-on` must match these:

```yaml
labels: [self-hosted, Linux, ARM64, container]   # default
```

### `resources`

Container resource limits:

```yaml
resources:
  memory: 8g        # RAM limit (default: 8g)
  cpus: 4           # CPU limit (default: 4)
  pids: 2048        # Max processes (default: 2048)
```

If your CI hits OOM errors, increase `memory` here and make sure your Colima VM has enough RAM allocated.

### `jobs`

Per-job image overrides. Use `base` for jobs that don't need the tools layer (faster, smaller image) and `full` for jobs that do:

```yaml
tools: [playwright, semgrep]

jobs:
  lint: base         # Language image only (~450 MB) — no tools
  test: base         # Language image only
  e2e: full          # Language + tools (~1 GB) — has Playwright
  security: full     # Language + tools — has Semgrep
```

### Examples

**Minimal** — just a runtime, nothing else. This is all most projects need:

```yaml
runtime: node:24
```

**With external service access** — your tests hit a database or deploy to a platform:

```yaml
runtime: node:24

egress:
  - "*.neon.tech"
  - "api.vercel.com"
```

**With a tool** — you run E2E browser tests in CI:

```yaml
runtime: node:24

tools:
  - playwright

egress:
  - "*.neon.tech"
```

**Kitchen sink** — multiple tools, per-job image overrides, custom resources:

```yaml
runtime: node:24

tools:
  - playwright
  - semgrep

apt:
  - libvips-dev

egress:
  - "*.neon.tech"
  - "api.vercel.com"

resources:
  memory: 12g
  cpus: 4
  pids: 2048

jobs:
  lint: base
  test: base
  e2e: full
  security: full
```

The progression is intentional — start minimal and add only what your CI actually requires.

---

## Network Egress Control

This is the core security feature. All outbound connections from the runner container are routed through a Squid proxy. The proxy evaluates each connection against a domain allowlist and blocks everything else.

### How It Works

The runner container sits on an internal Docker network with no direct internet access. The HTTP_PROXY and HTTPS_PROXY environment variables are set to point at the Squid proxy, which is the only path to the outside world.

For HTTPS connections, the proxy inspects the domain from the `CONNECT` request and allows or denies it. It does **not** perform TLS interception — the encrypted tunnel passes through opaquely. This means the proxy sees the destination domain but cannot read the traffic content.

```
┌──────────────────────────────────────────────────┐
│  Internal Docker Network (no direct internet)     │
│                                                    │
│  ┌─────────────┐        ┌──────────────────────┐ │
│  │ Runner      │───────>│ Squid Proxy          │ │
│  │ Container   │ HTTP_  │                      │ │
│  │             │ PROXY  │ Checks domain against│ │
│  └─────────────┘        │ allowlist:           │ │
│                          │  ✓ github.com       │─┼──> Internet
│                          │  ✓ registry.npmjs   │ │    (allowed only)
│                          │  ✓ pypi.org         │ │
│                          │  ✗ evil.com         │ │
│                          │  ✗ 169.254.169.254  │ │
│                          └──────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Base Allowlist (Always Included)

These domains are allowed for every project, regardless of configuration:

| Category | Domains |
|----------|---------|
| **GitHub** | `.github.com`, `api.github.com`, `.githubusercontent.com`, `.actions.githubusercontent.com`, `.objects.githubusercontent.com`, `.ghcr.io`, `.pkg.github.com`, `.pipelines.actions.githubusercontent.com` |
| **npm** | `.npmjs.org` |
| **PyPI** | `.pypi.org`, `.files.pythonhosted.org` |
| **Rust/Cargo** | `.crates.io`, `.rustup.rs`, `.rust-lang.org` |
| **CI Tools** | `.nodejs.org`, `.nodesource.com`, `.semgrep.dev`, `.googleapis.com`, `.playwright.azureedge.net` |

The base allowlist is defined in `infra/squid/base.conf`. To modify it, edit that file directly.

### Adding Project-Specific Domains

Add domains to the `egress` list in your `.github/runner.yml`. When the orchestrator starts, it merges the base allowlist with your project-specific domains to produce the runtime proxy configuration.

### What Gets Blocked

Everything not in the base allowlist or your `egress` list. This includes:

- Attacker-controlled servers (the primary exfiltration vector)
- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`)
- Tunneling services (ngrok, localtunnel)
- Social platforms used as exfiltration channels (Slack webhooks, Discord webhooks)
- Non-standard ports (only 80 and 443 are allowed)
- Raw IP HTTP requests to the internet (internal Docker network blocks direct access)

### Debugging Blocked Connections

If your CI job fails because a dependency needs to reach a domain that isn't allowlisted:

1. Check the proxy log for denied requests
2. Identify the domain
3. Add it to the `egress` list in your `runner.yml`
4. Restart the orchestrator

---

## Egress Model

RunSecure supports three types of outbound network access, each served by a different component inside the proxy container.

### HTTP/HTTPS (Squid)

The default. All HTTP and HTTPS traffic from the runner must pass through Squid on port 3128. Squid enforces a domain allowlist — requests to unlisted domains are blocked. TLS is not intercepted; the proxy sees the target hostname from the CONNECT request but not the encrypted payload.

Configure with `http_egress:` in `runner.yml`.

### Raw TCP (HAProxy)

For database clients, cache servers, and protocols that do not speak HTTP. When `tcp_egress:` entries are present, the orchestrator configures HAProxy inside the proxy container. Each `host:port` entry becomes a HAProxy frontend that the runner can reach via `proxy:<port>`.

Example: with `tcp_egress: [ep-foo.neon.tech:5432]`, the runner connects to `proxy:5432` and HAProxy transparently forwards to `ep-foo.neon.tech:5432`.

Configure with `tcp_egress:` in `runner.yml`.

### DNS (dnsmasq)

By default the runner inherits the Docker host's DNS resolver (`dns.host: true`). When `dns.host: false`, the orchestrator starts a dnsmasq instance inside the proxy container. The runner's `/etc/resolv.conf` is updated to point at the proxy.

This is useful when:
- Your CI uses private DNS names that are only resolvable via an internal resolver
- You want to provide a static hosts file for test fixtures
- You want to restrict which domain names the runner can resolve (via `whitelist_file`)

Configure with `dns:` in `runner.yml`.

### Installing client tools

Database and cache client libraries (e.g., `pg`, `redis`, `mysql2`) are just npm/pip packages — they install normally via `http_egress`. What `tcp_egress` enables is the actual TCP connection to the server at runtime.

You do not need any special tooling inside the image. The runner uses the client library's standard API; the TCP-level path to the server goes through HAProxy transparently.

For the postgres example:
```yaml
tcp_egress:
  - ep-foo.neon.tech:5432
```

Your Node.js code connects to the server exactly as it would outside RunSecure:
```js
import postgres from 'postgres'
const sql = postgres({ host: 'ep-foo.neon.tech', port: 5432 })
```

The `DATABASE_URL` environment variable (if used) should point to `ep-foo.neon.tech:5432` — not to `proxy:5432`. HAProxy is transparent; the runner's DNS resolves `ep-foo.neon.tech` to the proxy IP, and HAProxy routes based on the port.

Note: this requires `dns.host: false` with the correct DNS server so that `ep-foo.neon.tech` resolves to the proxy IP inside the container. If you use `dns.host: true` (the default), you need to configure the client to connect to `proxy:5432` explicitly.

---

## Image Architecture

Images are stackable. You only build what you need.

The simplest setup is two layers: base + language. That's a fully functional, hardened runner. Tools are a third layer you add only if your CI requires them.

```
                                        ┌─────────────────────────────┐
                                        │  finalize-hardening.sh      │
                     You stop here      ├─────────────────────────────┤
                     if you don't  ───> │  Tools (if you need them)   │
                     need tools         │  Playwright / Semgrep / ... │
┌─────────────────────────────────┐     ├─────────────────────────────┤
│  Language runtime               │ ──> │  Language runtime            │
│  Node.js / Python / Rust        │     │  Node.js / Python / Rust     │
├─────────────────────────────────┤     ├─────────────────────────────┤
│  runner-base                    │     │  runner-base                 │
│  Debian slim + GH Actions runner│     │  Debian slim + GH Actions    │
└─────────────────────────────────┘     └─────────────────────────────┘
      Most projects                          Only if tools: is set
```

**Base image** (`runner-base:latest`) — Debian bookworm-slim with the GitHub Actions runner binary, essential tools, a non-root user, and hardening applied. The `apt` package manager is deliberately kept at this stage so downstream layers can install packages.

**Language images** (`runner-node:24`, `runner-python:3.12`, `runner-rust:stable`) — add the language runtime on top of base. Each re-strips setuid bits in case the runtime install added any. **This is the image most projects will use directly.**

**Project images** (`runner-project:<hash>`) — generated only when you specify `tools` or `apt` in your config. Layers tool recipes on top of the language image, then runs `finalize-hardening.sh` which removes apt, re-strips setuid bits, and locks system paths. The image is tagged with a content hash of your configuration so that identical configs across different projects share the same cached image.

If your `runner.yml` only specifies `runtime` (no tools, no extra apt packages), the language image is used as-is — no project image is generated, no extra build step.

### Approximate Image Sizes

Most projects use just the language image:

| Image | Size | What you get |
|-------|------|-------------|
| `runner-node:24` | ~450 MB | Node.js + hardened base — enough for build, test, lint |
| `runner-python:3.12` | ~370 MB | Python + hardened base — enough for pytest, linting, packaging |
| `runner-rust:stable` | ~550 MB | Rust + hardened base — enough for cargo build, cargo test |

If you add tools, each one adds to the image:

| Tool | Additional size |
|------|----------------|
| Playwright + Chromium | +300 MB |
| Semgrep | +276 MB |
| Cypress | +250 MB |

---

## Security Hardening

RunSecure applies three independent layers of security. A breach of one layer does not compromise the others.

### Image Hardening (build-time)

Applied when the image is built. Reduces the attack surface available inside the container.

- **Non-root user** — the runner process runs as UID 1001, not root
- **No su/sudo** — privilege escalation binaries are deleted
- **Setuid bits stripped** — no binary can gain elevated privileges through setuid
- **Root account locked** — root shell is set to `/usr/sbin/nologin`
- **Package manager removed** — apt/dpkg are deleted in final images (attackers can't install tools)
- **Network recon tools removed** — no ping, nc, ssh, or wget
- **Persistence tools removed** — no crontab or at
- **SHA256-verified downloads** — the runner binary is verified by hash before extraction
- **Pinned package versions** — no version-swap supply chain attacks
- **Minimal PATH** — only essential directories

### Runtime Containment (launch-time)

Enforced by Docker flags when the container starts. Cannot be bypassed by anything inside the container.

| Flag | Protection |
|------|-----------|
| `--rm` | Container is destroyed after the job — no state persists |
| `--user 1001:0` | Process runs as non-root; system paths are root-owned and unwritable |
| `--cap-drop=ALL` | All Linux capabilities removed |
| `--security-opt=no-new-privileges` | Cannot gain new privileges via setuid/setgid at runtime |
| `--tmpfs /tmp:noexec` | `/tmp` is writable but cannot execute binaries |
| `--pids-limit` | Prevents fork bombs and unbounded process spawning |
| `--memory` / `--memory-swap` | Prevents memory exhaustion and OOM attacks |
| `--cpus` | Prevents CPU exhaustion (cryptomining) |
| Seccomp profile | Custom profile blocks dangerous syscalls: `ptrace`, `mount`, `bpf`, `keyctl`, kernel module loading, `perf_event_open`, `userfaultfd` |

### Network Isolation (network-level)

The runner container has no direct internet access. All traffic is routed through the Squid proxy on an internal Docker network. See [Network Egress Control](#network-egress-control) above.

---

## Known Limitations

### Per-step logs (resolved)

Earlier RunSecure releases destroyed the ephemeral runner container before per-step logs flushed to GitHub, causing `gh api .../jobs/<id>/logs` to return `BlobNotFound` on failed runs. This release adds a synchronous wait in the container entrypoint for the actions-runner's log-upload-complete marker before exit (default 30s timeout, configurable via `RUNSECURE_LOG_UPLOAD_TIMEOUT`). Logs are reliably retrievable from the GitHub UI for both successful and failed runs.

For operator-side recovery (network blips during upload, GitHub API hiccups), `_diag/` is host-mounted at the orchestrator's working directory. The latest run lives in `_diag/`; the previous run lives in `_diag.previous/`.

To disable the host-side bind mount entirely (security-sensitive shared-host scenarios), set `RUNSECURE_DIAG_RETENTION=0` in the orchestrator environment. The synchronous wait still applies; only the host-side fallback is dropped.

### TCP port collisions

Each `tcp_egress` port must be unique across all entries (one HAProxy frontend per port). If two services use the same port number, you cannot add both to `tcp_egress` without a port remapping workaround.

### No UDP egress

UDP traffic (DNS, QUIC, DTLS) is not proxied. When `dns.host: false`, DNS resolution goes through dnsmasq inside the proxy container — queries beyond the configured servers are blocked. Other UDP-based protocols are unsupported.

### CONNECT method only for HTTP/HTTPS

Squid uses the HTTP CONNECT method for HTTPS filtering. It does not perform SSL interception. This means the proxy can see the destination hostname but not the request path or payload. Some HTTP/1.0 clients that do not support CONNECT may fail.

### DNS log sensitivity

When `dns.host: false` and `dns.log_queries: true` (the default), dnsmasq logs all DNS queries to `_diag-proxy/`. On shared CI hosts, DNS queries may reveal internal service names. Set `dns.log_queries: false` or `RUNSECURE_DIAG_RETENTION=0` if this is a concern.

### Single runner per stack

Each `docker-compose` stack runs one runner. Multiple concurrent jobs require multiple orchestrator invocations. The `--max-jobs` flag controls how many jobs a single orchestrator processes sequentially.

### `runner.yml` field names are RunSecure-specific

The `.github/runner.yml` configuration file uses RunSecure-specific field names (`runtime:`, `egress:`, `tools:`, etc.). These fields are not recognized by GitHub-hosted runners. If you switch a job back to `runs-on: ubuntu-latest`, remove or ignore the `runner.yml` file.

---

## Orchestrator Options

```
./infra/scripts/run.sh [options]

Required:
  --project PATH     Path to the project directory (must have .github/runner.yml)
  --repo OWNER/REPO  GitHub repository (e.g., NaorPenso/my-app)

Optional:
  --max-jobs N       Maximum jobs to process before exiting (default: 5)
  --force            Force rebuild of the project image even if cached
  -h, --help         Show help
```

The orchestrator loops up to `--max-jobs` times, requesting a fresh JIT token from the GitHub API for each job. Press Ctrl+C to stop it between jobs.

---

## Testing

### Validation Tests

Per-image tests that verify hardening and functionality without any network (no proxy needed):

```bash
# Full suite: build all images + 36 security checks per image + functional tests
./tests/validation/run-all-tests.sh

# Quick mode: skip the Rust image (slow to build)
./tests/validation/run-all-tests.sh --quick

# Skip image builds: reuse already-built images
./tests/validation/run-all-tests.sh --skip-build
```

These tests run inside containers with the same hardening flags used in production. They verify: non-root user, no su/sudo, no setuid binaries, package manager neutered, no network tools, root account locked, system paths protected, /tmp noexec, writable workspace, core tools functional, language runtime present, and resource limits enforced.

### Integration Tests

End-to-end tests with the Squid proxy running. These prove the full system works as a unit:

```bash
# Full suite: egress + Node CI + Python CI + attack simulation (67 checks)
./tests/integration/run-integration-tests.sh

# Run individual test suites
./tests/integration/run-integration-tests.sh --test egress    # 25 egress proxy checks
./tests/integration/run-integration-tests.sh --test node       # Node.js CI lifecycle
./tests/integration/run-integration-tests.sh --test python     # Python CI lifecycle
./tests/integration/run-integration-tests.sh --test attack     # 28 attack vector checks

# Skip image builds
./tests/integration/run-integration-tests.sh --skip-build
```

**Egress tests** — verify that allowed domains (GitHub, npm, PyPI, crates.io) succeed and blocked domains (pastebin, webhook.site, ngrok, cloud metadata, Slack, Discord) are denied. Also checks that exfiltration techniques (POST requests, DNS-over-HTTPS, attacker webhooks) are blocked and that direct internet access bypassing the proxy is impossible.

**CI workflow tests** — run a real git clone, npm install, npm test, pip install, and pytest through the proxy to verify that real CI workloads succeed end-to-end.

**Attack simulation tests** — attempt 28 real attack vectors: Docker socket escape, host filesystem access, privilege escalation (setuid, capabilities), reverse shell tools, persistence mechanisms (cron, systemd, dotfiles), resource abuse (memory bombs, fork bombs), runtime package installation, namespace isolation, kernel attack surface (ptrace, insmod), and credential exposure.

---

## Extending RunSecure

### Adding a New Language

Create a new Dockerfile in `images/`. Follow the existing pattern:

1. Start `FROM runner-base:${BASE_TAG}`
2. Switch to `USER root`
3. Install the language runtime via apt or official installer
4. Re-strip setuid bits: `RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true`
5. Set the `PATH` (must include `/home/runner/actions-runner` and `/home/runner/actions-runner/bin`)
6. Switch back to `USER runner`

Example for Go:

```dockerfile
ARG BASE_TAG=latest
FROM runner-base:${BASE_TAG}
ARG GO_VERSION=1.22
USER root
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" | tar -C /usr/local -xzf -
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
ENV PATH="/usr/local/go/bin:/home/runner/actions-runner:/home/runner/actions-runner/bin:/usr/local/bin:/usr/bin:/bin"
USER runner
WORKDIR /home/runner
```

Build it: `docker build -f images/go.Dockerfile --build-arg GO_VERSION=1.22 -t runner-go:1.22 .`

Use it: `runtime: go:1.22`

### Adding a New Tool Recipe

Create a shell script in `tools/`. The script runs as root during image build and must:

1. Install any system dependencies via apt
2. Install the tool
3. Clean up apt lists (`rm -rf /var/lib/apt/lists/*`)
4. Verify the tool works

Example for Trivy:

```bash
#!/bin/bash
set -euo pipefail
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
trivy --version
echo "[RunSecure] Trivy installed successfully."
```

Make it executable: `chmod +x tools/trivy.sh`

Use it: `tools: [trivy]`

---

## Versioning and Updates

RunSecure uses container registry publishing for release management. When a new version is tagged (e.g., `v1.2.0`), GitHub Actions builds and pushes multi-arch images to GHCR:

```
ghcr.io/andend-collective/runsecure/base:1.2.0
ghcr.io/andend-collective/runsecure/node:1.2.0-24
ghcr.io/andend-collective/runsecure/python:1.2.0-3.12
ghcr.io/andend-collective/runsecure/rust:1.2.0-stable
ghcr.io/andend-collective/runsecure/proxy:1.2.0
```

### Consuming a published release

Add a `version:` field to your project's `.github/runner.yml`:

```yaml
version: "1.2.0"
runtime: node:24
egress:
  - "*.neon.tech"
```

The orchestrator will pull pre-built images from GHCR instead of building locally. Your egress domains, tools, resources, and labels remain yours — RunSecure never touches them.

If the pull fails (offline, version doesn't exist), the orchestrator falls back to building from local Dockerfiles automatically.

### What belongs to whom

| RunSecure (shipped via release) | Your project (in your repo) |
|---|---|
| Base image hardening | `runtime:` choice |
| Proxy base allowlist | `egress:` domains |
| Seccomp profile | `tools:` selection |
| Container runtime flags | `resources:` limits |
| Tool recipes | `labels:` |

These are merged at runtime — updating RunSecure never overwrites your project config. Updating your project config never changes the hardening.

### How updates flow

The orchestrator automatically pulls the latest project config (`git pull`) before reading `runner.yml`, so egress domain changes take effect on the next job without manual intervention on the runner host.

For RunSecure-side updates (new hardening, proxy changes), bump the `version:` in your project's `runner.yml` to the new release. The next job will pull the new images.

---

## Troubleshooting

### npm install hangs or times out

The proxy is likely blocking a domain that npm or one of your dependencies needs. Run the egress test to confirm the proxy is working, then check the proxy log for denied domains:

```bash
./tests/integration/run-integration-tests.sh --test egress
```

Add the missing domain to the `egress` list in your `runner.yml`.

### Permission denied errors

The container runs as UID 1001. Common fixes:
- Use `npm ci --cache /home/runner/.npm` if the default npm cache path is inaccessible
- Write build output to `/home/runner/_work/` (writable and ephemeral)
- Do not attempt to write to `/usr/local/`, `/etc/`, or other system paths

### Container exits immediately

The JIT token has likely expired (they last 1 hour). The orchestrator requests a fresh token for each job automatically, but if you're running the container manually, make sure the token is current.

### "apt-get: not found" inside the container

This is by design. Final images have the package manager removed. If a CI step needs a system package, add it to the `apt` list in your `runner.yml` so it's installed during image build, or create a tool recipe.

### Out of memory during npm ci or build

Increase the container memory limit:

```yaml
resources:
  memory: 12g
```

Also make sure your Colima VM has enough memory:

```bash
colima stop
colima start --cpu 4 --memory 20 --vm-type vz --mount-type virtiofs
```

### pip install fails with "externally-managed-environment"

RunSecure's Python image uses Debian's system Python, which enforces [PEP 668](https://peps.python.org/pep-0668/). Use a virtual environment in your workflow steps:

```yaml
- name: Install dependencies
  run: |
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

- name: Run tests
  run: |
    . .venv/bin/activate
    pytest
```

### Images are too large

Use per-job image overrides so lightweight jobs (lint, typecheck) use the smaller base image:

```yaml
tools: [playwright]
jobs:
  lint: base      # ~450 MB, no Playwright
  test: base
  e2e: full       # ~750 MB, with Playwright
```

---

## Project Layout

```
RunSecure/
├── images/                        # Docker images (layered)
│   ├── base.Dockerfile            #   Base: Debian slim + runner + hardening
│   ├── node.Dockerfile            #   + Node.js
│   ├── python.Dockerfile          #   + Python
│   └── rust.Dockerfile            #   + Rust
├── tools/                         # Tool install recipes (shell scripts)
│   ├── playwright.sh              #   Playwright + Chromium
│   ├── semgrep.sh                 #   Semgrep SAST scanner
│   └── cypress.sh                 #   Cypress E2E
├── infra/                         # Runtime infrastructure
│   ├── docker-compose.yml         #   Production compose (runner + proxy)
│   ├── squid/                     #   Egress proxy (Squid + HAProxy + dnsmasq)
│   │   ├── base.conf              #     Squid domain allowlist
│   │   ├── Dockerfile             #     Proxy image
│   │   ├── proxy-entrypoint.sh   #     Process supervisor
│   │   ├── haproxy.cfg.tmpl      #     HAProxy TCP config template
│   │   └── dnsmasq.conf.tmpl     #     dnsmasq DNS config template
│   ├── seccomp/
│   │   └── node-runner.json       #   Syscall filter profile
│   └── scripts/
│       ├── run.sh                 #   Main orchestrator
│       ├── compose-image.sh       #   Image builder (reads runner.yml)
│       ├── generate-egress-conf.sh #  Generates all proxy + compose config
│       ├── entrypoint.sh          #   Container startup (JIT config)
│       ├── finalize-hardening.sh  #   Final image hardening
│       └── lib/
│           ├── validate-schema.sh #   runner.yml schema validator
│           ├── fetch-runtime-file.sh # SSRF-protected file fetcher
│           ├── yaml-emit.sh       #   YAML fragment helpers
│           └── diag-rotation.sh  #   Diag directory rotation
├── skeleton/                      # Templates for new projects
│   ├── runner.yml                 #   Configuration template
│   ├── workflow-ci.yml            #   Example GitHub Actions workflow
│   └── ONBOARDING.md             #   Step-by-step setup guide
└── tests/
    ├── validation/                # Per-image hardening + functional tests
    ├── integration/               # End-to-end with proxy + attack sims
    └── {node,python,rust}-project/  # Test fixture projects
```

---

## License

MIT
