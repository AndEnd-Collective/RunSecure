---
name: developing-runsecure
description: Use when working ON the RunSecure codebase itself — adding a language/tool image, changing the orchestrator (Go), socket-proxy, egress generation, hardening, or the CI/release pipeline. Triggers when modifying RunSecure's Dockerfiles, infra/orchestrator, infra/socket-proxy, infra/squid, tools/, tests/, or .github/workflows.
---

# Developing RunSecure

RunSecure is a shell/Dockerfile/YAML project plus two Go modules (orchestrator, socket-proxy). Read `AGENTS.md` first — it lists architecture decisions and anti-patterns that are NOT up for re-litigation (each came from a real incident). This skill is the working playbook.

## Architecture (build bottom-up)

`debian:bookworm-slim` (digest-pinned) → `runner-base` (GH Actions runner + hardening) → `runner-{node,python,rust}:<ver>` → optional project image (`compose-image.sh` layers `tools/*.sh` then `finalize-hardening.sh`).

Runtime (Plan A orchestrator, Compose): `orchestrator` (distroless Go) polls GitHub → asks `socket-proxy` (the only thing mounting docker.sock; strict body validation) to spawn a per-job stack: one combined **proxy** (squid+haproxy+dnsmasq) + **runner**. The runner is on an `internal:true` network only; the proxy is dual-homed (internal + a deploy-provisioned `spawn-egress` network, ICC disabled) and enforces the `runner.yml` allowlist at L7. Per-spawn egress configs are delivered to the proxy via a shared **named volume** (`pat-init`/`egress-init` set ownership). Legacy single-job path: `infra/scripts/run.sh`.

## Key invariants (do not break)

- **No AI attribution** in commits/PRs/authorship (no `Co-Authored-By: Claude`, no 🤖 footers, no `cerebras.net`). `CLAUDE.md` and `.claude/` are gitignored by design.
- **Never weaken egress/grype security.** Keep `grype --fail-on high --only-fixed`. Unfixable upstream-bundled CVEs get a *specific* `.grype.yaml` entry (CVE/GHSA id + package + upstream + fix version + removal trigger), never a blanket suppression. The allowlist-hygiene test enforces justifications.
- **Runner is egress-isolated**: only `role=proxy` containers may attach the egress network/volume (socket-proxy `ValidateContainerCreate` gates both `EndpointsConfig` and `NetworkMode`). A project cannot self-authorize an override the scope didn't permit.
- **`apt-get upgrade -y` in every Dockerfile is load-bearing** (Debian CVEs). Don't remove for speed.
- **Build-args must be referenced + asserted.** Each language image has a build-time assertion that the installed runtime matches the build-arg (the `PYTHON_VERSION=3.12` → shipped 3.11 incident). Add the equivalent for any new language.
- **Pin everything by digest/version** and bump every pin to latest stable together (Dockerfile ARGs + checksums, image digests, GH Actions SHAs). Releases bump weekly via `weekly-version-bump.yml`.

## Build & test commands

```bash
# images
docker build -f images/base.Dockerfile -t runner-base:latest .
docker build -f images/node.Dockerfile --build-arg NODE_VERSION=24 -t runner-node:24 .

# Go (must stay >=95% coverage; modules: infra/orchestrator, infra/socket-proxy)
cd infra/orchestrator && go test ./... -cover
cd infra/socket-proxy && go test ./... -cover   # plus FuzzValidateContainerCreate

# host-only lints (fast; what validate.yml runs): workflow YAML, .grype.yaml hygiene,
# tool-recipe pins, compose hardening, schema validator, version-bump math
for t in tests/validation/test-*.sh; do bash "$t"; done

# full integration (proxy + orchestrator spawn + attack sims); needs Docker
./tests/integration/run-integration-tests.sh
./tests/integration/run-integration-tests.sh --test orch-egress   # single suite
```

Integration suites that spawn real proxies push test images through a local `registry:2` so they have real manifest digests (locally-built `{{.Id}}` config digests don't resolve via `containers/create` on CI Linux). The PAT is delivered to the orchestrator (UID 65532) at mode 0400 via a named volume — it enforces 0400.

## Common changes

- **Add a language/version:** new `images/<lang>.Dockerfile` (or case branch) with SHA256-verified install + the build-time version assertion; add to `publish-images.yml`, `post-publish-acceptance.yml`, and `promote-to-stable.yml` matrices.
- **Add a tool:** `tools/<tool>.sh` (runs as root, installs via apt, ends with cleanup), then `test-tool-recipes.sh`.
- **Orchestrator egress (Go):** `internal/runneryml` (schema: `http_egress`/`tcp_egress`/`dns`, validation), `internal/egress` (RenderSquid/RenderHAProxy/RenderDNSMasq — sanitize EVERY interpolated value against config injection), `internal/security` (Policy + override gate), `internal/docker/spawn.go`. Every behavioral change ships positive + negative + attacker tests.
- **Socket-proxy:** `internal/proxy/validate.go` (body-only validation; default-deny), `internal/imageallow` (digest-pinned allowlist). Keep the fuzz test green.

## Release

After merge, cut a version by triggering `weekly-version-bump.yml` (`bump_type: patch|minor|major`) — it tags, which fires `publish-images.yml` (canary) → `post-publish-acceptance.yml` → `promote-to-stable.yml` (server-side retag to `<ver>` + `latest`). The post-publish Grype gate must pass.

## Self-CI (dogfood)

When a PR has `lints-on-self` pending, run `./infra/scripts/dev/bootstrap-self-runner.sh` to drain the queue, then kill it (`kill $(cat _orchestrator-logs/orch.pid)`). No permanent runner.

Pushing over the HTTPS remote can hang on `git-credential-manager`; push with the gh token as a credential helper if needed.

Depth: `AGENTS.md` (operating principles), `SECURITY.md` (claim catalog), `README.md` (operational notes), `CLAUDE.md` (build/test/architecture quick-ref, local-only).
