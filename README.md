# RunSecure

Hardened, containerized GitHub Actions self-hosted runners with egress control.

Ephemeral containers. Domain-allowlisted networking. Multi-language. One config file per project.

---

## Why RunSecure

Bare-metal self-hosted runners are a security liability. A compromised GitHub Action or npm dependency can:

- Read SSH keys, AWS credentials, and browser cookies from the host
- Exfiltrate secrets via `curl` to an attacker-controlled server
- Persist across jobs by spawning background processes
- Pivot laterally via the host network

RunSecure eliminates these risks by running each CI job in a **hardened, ephemeral Docker container** with network egress filtered through a proxy. When the job finishes, the container is destroyed.

---

## Quick Start

### Prerequisites

```bash
# macOS
brew install docker yq

# Verify
docker --version   # Docker 20+
yq --version       # yq 4+
```

### 1. Build Images

```bash
cd /path/to/RunSecure

# Build the hardened base image
docker build -f images/base.Dockerfile -t runner-base:latest .

# Build language layer(s) you need
docker build -f images/node.Dockerfile \
  --build-arg NODE_VERSION=24 -t runner-node:24 .

docker build -f images/python.Dockerfile \
  --build-arg PYTHON_VERSION=3.12 -t runner-python:3.12 .

docker build -f images/rust.Dockerfile \
  --build-arg RUST_VERSION=stable -t runner-rust:stable .
```

### 2. Add Config to Your Project

Copy `skeleton/runner.yml` to your project:

```bash
cp /path/to/RunSecure/skeleton/runner.yml /path/to/your-project/.github/runner.yml
```

Edit it for your project's needs (see [Configuration](#configuration) below).

### 3. Run

```bash
# Start runner for your project
./infra/scripts/run.sh \
  --project /path/to/your-project \
  --repo owner/repo-name

# Without egress proxy (for debugging)
./infra/scripts/run.sh \
  --project /path/to/your-project \
  --repo owner/repo-name \
  --no-proxy
```

### 4. Validate

```bash
# Run the full test suite to verify everything works
./tests/validation/run-all-tests.sh --quick

# Run integration tests (egress proxy, CI workflows, attack simulation)
./tests/integration/run-integration-tests.sh
```

---

## Configuration

Each project needs one file: `.github/runner.yml`

### Full Schema

```yaml
# .github/runner.yml

# REQUIRED: Language runtime and version
runtime: node:24          # node:22 | python:3.12 | rust:stable

# OPTIONAL: CI tools to install on top of the language layer
# Available recipes: playwright, semgrep, cypress
tools:
  - playwright
  - semgrep

# OPTIONAL: Extra system packages (apt) to install
apt:
  - libvips-dev

# OPTIONAL: Additional domains allowed through the egress proxy
# The base allowlist (GitHub, npm, PyPI, crates.io) is always included.
egress:
  - "*.neon.tech"
  - "api.vercel.com"

# OPTIONAL: GitHub runner labels
labels: [self-hosted, Linux, ARM64, container]

# OPTIONAL: Container resource limits
resources:
  memory: 6g        # default: 4g
  cpus: 4           # default: 2
  pids: 1024        # default: 512
  workspace: 12g    # default: 8g (tmpfs size for _work)

# OPTIONAL: Per-job image overrides
# "base" = language image only (smaller, faster)
# "full" = language + all tools from the tools: list
jobs:
  lint: base
  test: base
  e2e: full
```

### Minimal Example

```yaml
# .github/runner.yml — simplest possible config
runtime: node:24
```

This gives you a hardened Node.js 24 runner with:
- Base egress allowlist (GitHub + npm)
- Default resource limits (4 GB RAM, 2 CPUs, 512 PIDs)
- Default labels `[self-hosted, Linux, ARM64, container]`

---

## Architecture

```
RunSecure/
├── images/                          # Docker images (layered)
│   ├── base.Dockerfile              #   Debian slim + runner binary + hardening
│   ├── node.Dockerfile              #   + Node.js runtime
│   ├── python.Dockerfile            #   + Python runtime
│   └── rust.Dockerfile              #   + Rust toolchain
│
├── tools/                           # Install recipes (shell scripts)
│   ├── playwright.sh                #   Playwright + Chromium
│   ├── semgrep.sh                   #   Semgrep SAST
│   └── cypress.sh                   #   Cypress E2E
│
├── infra/                           # Runtime infrastructure
│   ├── docker-compose.yml           #   Production: runner + proxy
│   ├── squid/                       #   Egress proxy
│   │   ├── base.conf                #     Base domain allowlist
│   │   └── Dockerfile               #     Proxy image
│   ├── seccomp/
│   │   └── node-runner.json         #   Syscall filter profile
│   └── scripts/
│       ├── run.sh                   #   Main orchestrator
│       ├── compose-image.sh         #   Image builder (reads runner.yml)
│       ├── generate-squid-conf.sh   #   Merges base + project egress
│       ├── entrypoint.sh            #   Container startup (JIT config)
│       └── finalize-hardening.sh    #   Final image hardening (removes apt)
│
├── skeleton/                        # Copy to new projects
│   ├── runner.yml                   #   Template configuration
│   ├── workflow-ci.yml              #   Example GitHub Actions workflow
│   └── ONBOARDING.md               #   Step-by-step setup guide
│
└── tests/
    ├── validation/                  # Unit-level container tests
    │   ├── run-all-tests.sh         #   Build + security + functional tests
    │   ├── validate-runner.sh       #   In-container hardening checks (36 checks)
    │   └── validate-network.sh      #   Egress allowlist/blocklist checks
    ├── integration/                 # End-to-end with proxy
    │   ├── run-integration-tests.sh #   Full integration orchestrator
    │   ├── docker-compose.test.yml  #   Test compose (proxy + runner)
    │   ├── test-egress-proxy.sh     #   25 egress checks
    │   ├── test-ci-workflow-node.sh #   Real Node CI lifecycle
    │   ├── test-ci-workflow-python.sh # Real Python CI lifecycle
    │   └── test-attack-simulation.sh  # 28 attack vector checks
    ├── node-project/                # Test project: Node.js
    ├── python-project/              # Test project: Python
    └── rust-project/                # Test project: Rust
```

### Image Layer Cake

```
┌─────────────────────────────────────┐
│  finalize-hardening.sh              │  removes apt, strips setuid
│  (only in composed images)          │  via compose-image.sh
├─────────────────────────────────────┤
│  Tools (optional)                   │  Playwright, Semgrep, Cypress
│  from tools/*.sh recipes            │  ~250-300 MB each
├─────────────────────────────────────┤
│  Language runtime                   │  Node / Python / Rust
│  from images/{lang}.Dockerfile      │  ~120-200 MB
├─────────────────────────────────────┤
│  runner-base                        │  Debian slim + GH Actions runner
│  from images/base.Dockerfile        │  + git, curl, jq, gh CLI
│                                     │  ~320 MB
└─────────────────────────────────────┘
```

### Network Architecture

```
┌──────────────────────────────────────────────────┐
│  Internal Docker Network (no internet access)     │
│                                                    │
│  ┌─────────────┐        ┌──────────────────────┐ │
│  │ Runner      │───────▶│ Squid Proxy          │ │
│  │ (ephemeral) │ HTTP_  │ (egress gate)        │ │
│  │             │ PROXY  │                      │ │
│  └─────────────┘        │ Allows:              │ │
│                          │  github.com          │─┼──▶ Internet
│                          │  registry.npmjs.org  │ │    (allowed only)
│                          │  pypi.org            │ │
│                          │  + project egress    │ │
│                          │                      │ │
│                          │ Blocks:              │ │
│                          │  everything else     │ │
│                          └──────────────────────┘ │
└──────────────────────────────────────────────────┘
```

---

## How It Works

### Image Building

When you run `./infra/scripts/run.sh --project /path/to/project`, the orchestrator:

1. Reads `.github/runner.yml` from your project
2. Checks if the language base image exists (e.g., `runner-node:24`)
3. If `tools:` are specified, `compose-image.sh` generates a Dockerfile:
   ```dockerfile
   FROM runner-node:24
   USER root
   # Tool: playwright (from tools/playwright.sh)
   COPY tools/playwright.sh /tmp/install-playwright.sh
   RUN /tmp/install-playwright.sh && rm /tmp/install-playwright.sh
   # Finalize hardening (removes apt, strips setuid)
   COPY infra/scripts/finalize-hardening.sh /tmp/finalize-hardening.sh
   RUN /tmp/finalize-hardening.sh
   USER runner
   ```
4. Builds with a **content-hash tag** (e.g., `runner-project:a3f8c1d2e4f5`). Same config = same hash = Docker cache hit.

### Job Execution

1. Orchestrator requests a **JIT (Just-In-Time) token** from GitHub API
2. Generates Squid proxy config (base allowlist + project egress domains)
3. Launches runner container via `docker-compose` with full hardening flags
4. Container runs a single job and exits
5. Container is destroyed (`--rm`)
6. Loop for next job

### What Happens Inside the Container

- **User**: `runner` (UID 1001), not root
- **Filesystem**: Read-only root, writable tmpfs at `/tmp` and `/home/runner/_work`
- **Network**: All traffic routes through Squid proxy on internal Docker network
- **Capabilities**: All dropped (`--cap-drop=ALL`)
- **Privileges**: Cannot escalate (`--security-opt=no-new-privileges`)
- **Processes**: Capped by `--pids-limit`
- **Memory/CPU**: Capped by resource limits
- **/tmp**: Writable but `noexec` (can't run downloaded binaries)

---

## Supported Runtimes

| Runtime | Build Command | Image Size |
|---------|--------------|------------|
| Node.js 24 | `docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .` | ~450 MB |
| Node.js 22 | `docker build -f images/node.Dockerfile --build-arg NODE_VERSION=22 -t runner-node:22 .` | ~450 MB |
| Python 3.12 | `docker build -f images/python.Dockerfile --build-arg PYTHON_VERSION=3.12 -t runner-python:3.12 .` | ~370 MB |
| Rust stable | `docker build -f images/rust.Dockerfile --build-arg RUST_VERSION=stable -t runner-rust:stable .` | ~550 MB |

## Available Tool Recipes

| Tool | Recipe | Size Impact | Requires |
|------|--------|-------------|----------|
| Playwright + Chromium | `tools/playwright.sh` | ~300 MB | Node.js |
| Semgrep | `tools/semgrep.sh` | ~276 MB | Python 3 (auto-installed if missing) |
| Cypress | `tools/cypress.sh` | ~250 MB | Node.js |

---

## Egress Proxy

### Base Allowlist (always included)

| Category | Domains |
|----------|---------|
| **GitHub** | `.github.com`, `api.github.com`, `.githubusercontent.com`, `.actions.githubusercontent.com`, `.ghcr.io`, `.pkg.github.com` |
| **npm** | `.npmjs.org` |
| **PyPI** | `.pypi.org`, `.files.pythonhosted.org` |
| **Rust** | `.crates.io`, `.rustup.rs`, `.rust-lang.org` |
| **CI tools** | `.nodejs.org`, `.nodesource.com`, `.semgrep.dev`, `.googleapis.com`, `.playwright.azureedge.net` |

### Adding Project-Specific Domains

In your `.github/runner.yml`:

```yaml
egress:
  - "*.neon.tech"          # Neon database
  - "api.vercel.com"       # Vercel deployments
  - "*.supabase.co"        # Supabase
  - "*.amazonaws.com"      # AWS services
```

### Everything Else Is Blocked

Any domain not in the base allowlist or your project's `egress:` list is denied. This blocks:
- Exfiltration to attacker servers
- Cloud metadata endpoints (169.254.169.254)
- Tunneling services (ngrok, localtunnel)
- Social platforms (Slack, Discord) used as exfil channels

---

## Testing

### Validation Tests (per-image, no proxy)

Tests that each image is correctly hardened and functional:

```bash
# Full suite: build images + security checks + functional tests
./tests/validation/run-all-tests.sh

# Quick (skip Rust build)
./tests/validation/run-all-tests.sh --quick

# Reuse cached images
./tests/validation/run-all-tests.sh --skip-build
```

**What it tests (36 checks per image):**
- Non-root user, no su/sudo, no setuid binaries
- Package manager neutered, no network tools
- Root account locked, read-only filesystem
- Writable workspace and /tmp
- Core tools (git, curl, jq, gh) functional
- Language runtime present and working
- Resource limits (PID, memory, CPU) enforced

### Integration Tests (with proxy)

End-to-end tests with the Squid egress proxy active:

```bash
# Full suite
./tests/integration/run-integration-tests.sh

# Individual suites
./tests/integration/run-integration-tests.sh --test egress   # 25 egress checks
./tests/integration/run-integration-tests.sh --test node      # Node CI lifecycle
./tests/integration/run-integration-tests.sh --test python    # Python CI lifecycle
./tests/integration/run-integration-tests.sh --test attack    # 28 attack simulations

# Skip image builds
./tests/integration/run-integration-tests.sh --skip-build
```

**What it tests (67 checks total):**
- Allowed domains succeed (GitHub, npm, PyPI, crates.io)
- Blocked domains denied (pastebin, webhook.site, ngrok, metadata endpoints)
- Real `git clone` + `npm install` + `npm test` through proxy
- Real `pip install` + `pytest` through proxy
- Docker socket escape, host filesystem access, privilege escalation
- Reverse shell tools, persistence mechanisms, resource abuse
- Runtime package installation, namespace isolation, credential exposure

---

## Updating GitHub Workflows

Your workflow `runs-on:` labels need to match the runner config. Change:

```yaml
# Before (bare-metal macOS)
runs-on: [self-hosted, macOS, ARM64]

# After (containerized Linux)
runs-on: [self-hosted, Linux, ARM64, container]
```

The `Setup Node.js` step is no longer needed (Node is baked into the image), but it's harmless to leave it.

---

## Adding a New Language

1. Create `images/go.Dockerfile`:
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

2. Build: `docker build -f images/go.Dockerfile --build-arg GO_VERSION=1.22 -t runner-go:1.22 .`

3. Use in a project: `runtime: go:1.22`

## Adding a New Tool Recipe

1. Create `tools/trivy.sh`:
   ```bash
   #!/bin/bash
   set -euo pipefail
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   trivy --version
   echo "[RunSecure] Trivy installed successfully."
   ```

2. Make executable: `chmod +x tools/trivy.sh`

3. Use in a project: `tools: [trivy]`

---

## Troubleshooting

### "npm install" hangs or times out

The proxy may be blocking a domain npm needs. Run the egress test first:
```bash
./tests/integration/run-integration-tests.sh --test egress
```
If needed, add the missing domain to `egress:` in your `runner.yml`.

### "Permission denied" errors in CI

The container runs as UID 1001. Check that your workflow doesn't assume root access. Common fixes:
- Use `npm ci --cache /home/runner/.npm` instead of default cache paths
- Write build output to `/home/runner/_work/` (writable tmpfs)
- Don't write to `/usr/local/` or other system paths

### Container exits immediately

Check that the JIT token is valid. Tokens expire after 1 hour. If using the orchestrator, it requests a fresh token for each job.

### "apt-get: not found" inside the container

This is intentional. The package manager is removed in finalized images. If a tool needs apt, create a [tool recipe](#adding-a-new-tool-recipe) that installs the dependency during image build.

### Images are too large

Use per-job image overrides to avoid loading unnecessary tools:
```yaml
jobs:
  lint: base        # ~450 MB (no Playwright/Semgrep)
  test: base
  e2e: full         # ~1 GB (with Playwright)
```
