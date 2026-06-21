Adopt RunSecure to harden this project's GitHub Actions CI: run each job in a hardened, ephemeral Docker container whose only network path is a default-deny, allowlist-only egress proxy. One job per container, then destroyed. RunSecure is a separate repo (clone it); this project only needs `.github/runner.yml` + matching workflow labels.

Non-negotiable rules:
- Egress is default-deny. Everything the build reaches must be declared in `runner.yml` (`http_egress` for HTTP/HTTPS domains, `tcp_egress` for raw TCP `host:port`). Never disable the proxy.
- Images are terminal: never `FROM ghcr.io/andend-collective/runsecure/*` to add tools. Tools go via `runner.yml` `tools:`/`apt:`.
- A project cannot self-authorize private-range egress; reaching internal IPs needs an operator scope override (`security_overrides.allow_private_cidrs`). Surface that, don't work around it.

Do this:
1. Inspect the repo to determine the runtime (node:24/node:22/python:3.12/rust:stable) and which hosts the build legitimately fetches from (registries, mirrors, databases). Map them to `http_egress` (domains) and `tcp_egress` (`host:port`, unique ports, not 80/443).
2. Write `.github/runner.yml` (2.0.0 schema): `runtime`, `labels`, optional `tools`/`apt`, `http_egress`, `tcp_egress`, optional `dns`, `resources`. Use `http_egress` (NOT the deprecated `egress.allow_domains`). Validate with `infra/scripts/lib/validate-schema.sh`.
3. Set the workflow `runs-on` to exactly the `labels` from `runner.yml`.
4. Build images (`docker build -f images/base.Dockerfile -t runner-base:latest .` then the language layer) or pin `version:` to a published release; or `infra/scripts/compose-image.sh /path/to/project` for a project image with tools.
5. Run: `infra/scripts/run.sh --project <dir> --repo owner/repo` (one job) or the orchestrator stack (persistent pool).
6. Verify: a labeled job is picked up and the container destroyed after; an allowed egress target works, a non-allowed one is blocked.

Report the generated `runner.yml`, the `runs-on` change, each egress entry tied to its build dependency, and any operator action needed. Depth: RunSecure `README.md`, `SECURITY.md`, `AGENTS.md`.
