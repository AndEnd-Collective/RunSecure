Adopt RunSecure to harden this project's GitHub Actions CI: run each job in a hardened, ephemeral Docker container whose only network path is a default-deny, allowlist-only egress proxy. One job per container, then destroyed. RunSecure is a separate repo (clone it); this project only needs `.github/runner.yml` + matching workflow labels.

Non-negotiable rules:
- Egress is default-deny. Everything the build reaches must be declared in `runner.yml` (`http_egress` for HTTP/HTTPS domains, `tcp_egress` for raw TCP `host:port`). Never disable the proxy.
- Images are terminal: never `FROM ghcr.io/andend-collective/runsecure/*` to add tools. Tools go via `runner.yml` `tools:`/`apt:`.
- A project cannot self-authorize private-range egress; reaching internal IPs needs an operator scope override (`security_overrides.allow_private_cidrs`). Surface that, don't work around it.

Deployment backends: Compose (default; `infra/scripts/run.sh` or orchestrator stack) or Kubernetes (`scope.backend: kube`; Helm chart at `charts/runsecure-orchestrator/`; requires NetworkPolicy-enforcing CNI — see `install-kubernetes.md`). The runner.yml egress schema (`http_egress`/`tcp_egress`/`dns`) is identical either way. The orchestrator can authenticate as a PAT (`auth.type: pat`) or GitHub App (`auth.type: github_app`).

Do this:
1. Inspect the repo to determine the runtime (node:24/node:22/python:3.12/rust:stable) and which hosts the build legitimately fetches from (registries, mirrors, databases). Map them to `http_egress` (domains) and `tcp_egress` (`host:port`, unique ports, not 80/443).
2. Write `.github/runner.yml`: `runtime`, `labels`, optional `tools`/`apt`, `http_egress`, `tcp_egress`, optional `dns`, `resources`. Use `http_egress` (NOT the deprecated `egress.allow_domains`). Validate with `infra/scripts/lib/validate-schema.sh`.
3. Set the workflow `runs-on` to exactly the `labels` from `runner.yml`.
4. Build images (`docker build -f images/base.Dockerfile -t runner-base:latest .` then the language layer) or pin `version:` to a published release; or `infra/scripts/compose-image.sh /path/to/project` for a project image with tools.
5. Run: `infra/scripts/run.sh --project <dir> --repo owner/repo` (one job), the orchestrator stack (Compose persistent pool), or the Helm chart (Kubernetes).
6. Verify: a labeled job is picked up and the container destroyed after; an allowed egress target works, a non-allowed one is blocked.

Report the generated `runner.yml`, the `runs-on` change, each egress entry tied to its build dependency, and any operator action needed. Depth: RunSecure `README.md`, `SECURITY.md`, `AGENTS.md`.
