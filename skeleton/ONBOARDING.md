# Onboarding Your Project to RunSecure

This guide walks you through adding RunSecure containerized runners to an existing project.

---

## Step 1: Copy Configuration (30 seconds)

Copy the runner config template into your project:

```bash
# From your project root
mkdir -p .github
cp /path/to/RunSecure/skeleton/runner.yml .github/runner.yml
```

Edit `.github/runner.yml` for your project. At minimum, set the `runtime:` to match your language:

```yaml
# Node.js project
runtime: node:24

# Python project
runtime: python:3.12

# Rust project
runtime: rust:stable
```

## Step 2: Add Project-Specific Egress Domains (1 minute)

If your CI needs to reach services beyond GitHub and your package registry, add them to the `egress:` list:

```yaml
egress:
  - "*.neon.tech"       # Neon database
  - "api.vercel.com"    # Vercel deployments
  - "*.supabase.co"     # Supabase
  - "*.amazonaws.com"   # AWS
  - "*.azure.com"       # Azure
```

If you're unsure what domains your CI needs, start without `egress:` and add domains as needed when the proxy blocks them.

## Step 3: Update Workflow Labels (1 minute)

In your `.github/workflows/*.yml`, change `runs-on:` to match the RunSecure labels:

```yaml
# Before
runs-on: [self-hosted, macOS, ARM64]
# or
runs-on: ubuntu-latest

# After
runs-on: [self-hosted, Linux, ARM64, container]
```

You can also copy `skeleton/workflow-ci.yml` as a starting point for a new workflow.

## Step 4: Build Images (one-time, ~5 minutes)

On the machine that will host the runners:

```bash
cd /path/to/RunSecure

# Always needed
docker build -f images/base.Dockerfile -t runner-base:latest .

# Build for your language
docker build -f images/node.Dockerfile \
  --build-arg NODE_VERSION=24 -t runner-node:24 .
```

## Step 5: Start the Runner

```bash
cd /path/to/RunSecure

# With egress proxy (recommended)
./infra/scripts/run.sh \
  --project /path/to/your-project \
  --repo owner/repo-name

# Without proxy (for initial debugging)
./infra/scripts/run.sh \
  --project /path/to/your-project \
  --repo owner/repo-name \
  --no-proxy
```

The runner will register with GitHub, pick up queued jobs, and process them in ephemeral containers.

## Step 6: Push and Verify

Push a commit or open a PR. Watch the GitHub Actions tab to see your workflow running on the containerized runner.

## Step 7: Commit the Config

```bash
git add .github/runner.yml
git commit -m "chore: add RunSecure runner configuration"
```

---

## Checklist

- [ ] `.github/runner.yml` added to project
- [ ] `runtime:` set to correct language and version
- [ ] `egress:` domains added (if needed)
- [ ] `tools:` added (if using Playwright, Semgrep, etc.)
- [ ] Workflow `runs-on:` labels updated
- [ ] Runner images built on host machine
- [ ] Orchestrator started and processing jobs
- [ ] First workflow run confirmed green

---

## Common Adjustments

### My CI needs more memory

```yaml
resources:
  memory: 8g    # default is 4g
```

### My E2E tests need Playwright

```yaml
tools:
  - playwright
```

### I have jobs that don't need extra tools

Use per-job overrides to save time and image size:

```yaml
tools: [playwright, semgrep]
jobs:
  lint: base       # no tools — small image, fast startup
  test: base
  e2e: full        # full image with Playwright
  security: full   # full image with Semgrep
```

### My workflow uses `setup-node` / `setup-python`

You can remove it — the runtime is already in the image. If you keep it, it will find the pre-installed version and proceed normally. No harm either way.
