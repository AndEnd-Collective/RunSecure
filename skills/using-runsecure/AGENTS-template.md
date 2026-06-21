# AGENTS.md — this project's CI runs on RunSecure

> Template: copy to your project root as `AGENTS.md`. Read by Claude Code, Codex, and other agents. Tells them how CI is constrained here so they don't fight the sandbox.

This repository's GitHub Actions jobs run on **RunSecure**: each job executes in a hardened, ephemeral Docker container (non-root, setuid stripped, no apt, read-only `/etc`, seccomp, `cap_drop ALL`) whose **only** network path is a proxy enforcing a **default-deny, allowlist-only** egress policy. One job per container, then destroyed.

## Rules for any change you make here

- **Network egress is allowlisted in `.github/runner.yml`, not in the workflow.** If a build step needs to reach a host, add it there:
  - HTTP/HTTPS domain → `http_egress:` (e.g. `.npmjs.org`, `api.github.com`; `.x.com` matches subdomains)
  - Raw TCP (databases, etc.) → `tcp_egress:` as `host:port` (unique ports; not 80/443; the app connects to `proxy:<port>`)
  Anything not listed is blocked by design. Don't try to disable the proxy or add `--no-proxy`. Don't add network calls to a step without adding the corresponding allowlist entry.
- **Use `http_egress`, not `egress.allow_domains`** (the old key is a deprecated alias that logs a WARNING and is removed in RunSecure 3.0).
- **Don't reach private/internal IPs from CI** unless the RunSecure operator has opted that range in at scope level — a project can't self-authorize it. Prefer hostnames that resolve publicly, or ask the operator.
- **Don't layer tools onto the runner image** (`FROM ghcr.io/andend-collective/runsecure/*` is forbidden — the hardening is final). CI tools come from `runner.yml` `tools:`/`apt:`.
- **`runs-on` must match `runner.yml` `labels` exactly** (e.g. `[self-hosted, Linux, ARM64, container]`). Changing labels in one place means changing both.
- **Jobs are ephemeral and single-use.** Don't rely on state persisting between steps beyond the workspace, or between jobs at all.

## Backend transparency

CI may run on the Compose backend or the Kubernetes backend, but the egress rules in `.github/runner.yml` are identical either way — you don't need to know which backend is running to add an egress entry or diagnose a network failure.

## When CI fails on network/egress
The first question is "is the target in `runner.yml`'s `http_egress`/`tcp_egress`?" — not "how do I bypass the proxy?". Add the host (with a one-line justification), or confirm with the operator if it's a private range.

## Where things are
- Egress + image config: `.github/runner.yml`
- RunSecure docs (if vendored or linked): `README.md` (consumption, egress proxy), `SECURITY.md` (guarantees).
