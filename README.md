# RunSecure

Hardened, containerized GitHub Actions self-hosted runners.

Ephemeral containers with security hardening, network egress control, and multi-language support. One config file per project.

## Quick Start

```bash
# Prerequisites
brew install yq docker

# Build base + Node runner
docker build -f images/base.Dockerfile -t runner-base:latest .
docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .

# Run for a project
./infra/scripts/run.sh --project /path/to/your/project --repo owner/repo
```

## Project Configuration

Add `.github/runner.yml` to your project:

```yaml
runtime: node:24
tools: [playwright, semgrep]
egress:
  - "*.neon.tech"
  - "api.vercel.com"
labels: [self-hosted, Linux, ARM64, container]
resources:
  memory: 6g
  cpus: 4
```

## Supported Runtimes

| Runtime | Image | Dockerfile |
|---------|-------|-----------|
| Node.js | `runner-node:24` | `images/node.Dockerfile` |
| Python | `runner-python:3.12` | `images/python.Dockerfile` |
| Rust | `runner-rust:stable` | `images/rust.Dockerfile` |

## Security Hardening

- Non-root user (UID 1001)
- All Linux capabilities dropped
- Read-only root filesystem
- No package manager in final image
- Setuid/setgid binaries stripped
- Dangerous tools removed (su, sudo, ssh, ping, netcat)
- Root account locked
- Seccomp syscall filtering
- PID, memory, and CPU limits
- Egress proxy with domain allowlist
- Ephemeral containers (destroyed after each job)
- SHA256-verified binary downloads

## Validation

```bash
# Run full validation suite
./tests/validation/run-all-tests.sh

# Quick mode (skip Rust)
./tests/validation/run-all-tests.sh --quick

# Reuse cached images
./tests/validation/run-all-tests.sh --skip-build
```

## Architecture

```
images/          — Dockerfiles (base + language layers)
tools/           — Tool install recipes (playwright, semgrep, cypress)
infra/           — Docker Compose, Squid proxy, seccomp profiles, scripts
tests/           — Test projects (Node, Python, Rust) + validation suite
```
