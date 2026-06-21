---
name: developing-runsecure
description: Use when working ON the RunSecure codebase itself — adding a language/tool image, changing the orchestrator (Go), socket-proxy, egress generation, hardening, or the CI/release pipeline. Triggers when modifying RunSecure's Dockerfiles, infra/orchestrator, infra/socket-proxy, infra/squid, tools/, tests/, or .github/workflows.
---

# Developing RunSecure

RunSecure is a shell/Dockerfile/YAML project plus two Go modules (orchestrator, socket-proxy). Read `AGENTS.md` first — it lists architecture decisions and anti-patterns that are NOT up for re-litigation (each came from a real incident). This skill is the working playbook.

## Architecture (build bottom-up)

`debian:bookworm-slim` (digest-pinned) → `runner-base` (GH Actions runner + hardening) → `runner-{node,python,rust}:<ver>` → optional project image (`compose-image.sh` layers `tools/*.sh` then `finalize-hardening.sh`).

Runtime (orchestrator, Compose backend): `orchestrator` (distroless Go) polls GitHub → asks `socket-proxy` (the only thing mounting docker.sock; strict body validation) to spawn a per-job stack: one combined **proxy** (squid+haproxy+dnsmasq) + **runner**. The runner is on an `internal:true` network only; the proxy is dual-homed (internal + a deploy-provisioned `spawn-egress` network, ICC disabled) and enforces the `runner.yml` allowlist at L7. Per-spawn egress configs are delivered to the proxy via a shared **named volume** (`pat-init`/`egress-init` set ownership).

**Backend abstraction** (`internal/backend/backend.go`): the `Backend` interface (`Spawn`, `WaitForExit`, `Teardown`, `Reconcile`, `Name`) decouples the orchestrator from the spawn mechanism. Implementations live in `internal/backend/compose/compose.go` and `internal/backend/kube/kube.go`. The kube backend creates per-spawn runner Pod + proxy Pod + ClusterIP Service + three NetworkPolicies (`RunnerEgressNetworkPolicy`, `ProxyEgressNetworkPolicy`, `ProxyIngressNetworkPolicy` — all three are load-bearing under a CNI enforcing NetworkPolicy; see `AGENTS.md`) + a GC-owner Secret in a per-scope namespace; runner.yml fetched via GitHub API.

**`internal/kube`**: object builders (`objects.go`) and client (`client.go`) used exclusively by the kube backend. Don't import from orchestrator or composition roots — keep the dependency direction clean.

**`internal/auth`**: `Provider` interface with two implementations — `pat.go` (reads a mode-0400 PAT file) and `githubapp.go` (mints RS256 JWTs, exchanges for installation access tokens, caches with 60 s refresh buffer). Select via scope config `auth_type: pat | github_app`.

**Socket-proxy mTLS**: optional mutual TLS on the socket-proxy listener (`RUNSECURE_SP_TLS_MODE=mtls`). When enabled, the proxy serves on `:2376`; the orchestrator's Docker client presents its client cert. The socket-proxy `internal/config/config.go` validates the mode and builds a TLS 1.3 `tls.Config` with `RequireAndVerifyClientCert`. Default is `plaintext` (`:2375`). The Helm chart's `tls.enabled` flag wires this up via cert-manager.

Legacy single-job path: `infra/scripts/run.sh`.

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

# Go (logic packages must stay ≥99% statement coverage; gated by test-go-coverage.sh)
# Composition roots (cmd/) are covered by integration, not unit tests.
cd infra/orchestrator && go test ./... -cover
cd infra/socket-proxy && go test ./... -cover   # plus FuzzValidateContainerCreate

# coverage gate (run as part of validate.yml)
bash tests/validation/test-go-coverage.sh

# host-only lints (fast; what validate.yml runs): workflow YAML, .grype.yaml hygiene,
# tool-recipe pins, compose hardening, schema validator, version-bump math
for t in tests/validation/test-*.sh; do bash "$t"; done

# full integration (proxy + orchestrator spawn + attack sims); needs Docker
./tests/integration/run-integration-tests.sh
./tests/integration/run-integration-tests.sh --test orch-egress   # single suite

# Kubernetes integration (kind + Calico; CNI must enforce NetworkPolicy)
./tests/integration/k8s/run-k8s-tests.sh
```

Integration suites that spawn real proxies push test images through a local `registry:2` so they have real manifest digests (locally-built `{{.Id}}` config digests don't resolve via `containers/create` on CI Linux). The PAT is delivered to the orchestrator (UID 65532) at mode 0400 via a named volume — it enforces 0400.

## Common changes

- **Add a language/version:** new `images/<lang>.Dockerfile` (or case branch) with SHA256-verified install + the build-time version assertion; add to `publish-images.yml`, `post-publish-acceptance.yml`, and `promote-to-stable.yml` matrices.
- **Add a tool:** `tools/<tool>.sh` (runs as root, installs via apt, ends with cleanup), then `test-tool-recipes.sh`.
- **Orchestrator egress (Go):** `internal/runneryml` (schema: `http_egress`/`tcp_egress`/`dns`, validation), `internal/egress` (RenderSquid/RenderHAProxy/RenderDNSMasq — sanitize EVERY interpolated value against config injection), `internal/security` (Policy + override gate), `internal/docker/spawn.go`. Every behavioral change ships positive + negative + attacker tests.
- **Backend abstraction:** implement `backend.Backend` in a new `internal/backend/<name>/` package. The `SpawnInput` struct is the seam between the orchestrator and both backends. Don't reach into backend-specific packages from the orchestrator directly.
- **Kube backend or object builders:** `internal/backend/kube/kube.go` + `internal/kube/{objects,client}.go`. Adding a new NetworkPolicy or resource type: update `objects.go`, add a test in `objects_test.go`, run the k8s integration suite to confirm CNI enforcement.
- **Auth provider:** `internal/auth/`. Adding a new provider: implement `auth.Provider` (`Token(ctx) (string, error)`), add unit tests (inject failures via the package-level `var` hooks as done in `githubapp_test.go`). Don't log token values.
- **Socket-proxy:** `internal/proxy/validate.go` (body-only validation; default-deny), `internal/imageallow` (digest-pinned allowlist), `internal/config/config.go` (TLS mode). Keep the fuzz test green. To enable mTLS, set `RUNSECURE_SP_TLS_MODE=mtls` and supply cert/key/CA env vars; the Helm chart's `tls.enabled` flag does this automatically.
- **Helm chart:** `charts/runsecure-orchestrator/`. Changes to scope config or auth fields must be reflected in `values.yaml`, `values.schema.json`, and the relevant `templates/`. Run `helm lint` and `helm template` to validate before pushing.
- **Weekly pin bumps:** `weekly-version-bump.yml` runs `go get -u` in both Go modules and bumps image/action pins. The post-promote coverage test (`promote-to-stable.yml`) re-runs `test-go-coverage.sh` to confirm coverage didn't regress after dependency updates.

## Release

After merge, cut a version by triggering `weekly-version-bump.yml` (`bump_type: patch|minor|major`) — it tags, which fires `publish-images.yml` (canary) → `post-publish-acceptance.yml` → `promote-to-stable.yml` (server-side retag to `<ver>` + `latest`). The post-publish Grype gate must pass.

## Self-CI (dogfood)

When a PR has `lints-on-self` pending, run `./infra/scripts/dev/bootstrap-self-runner.sh` to drain the queue, then kill it (`kill $(cat _orchestrator-logs/orch.pid)`). No permanent runner.

Pushing over the HTTPS remote can hang on `git-credential-manager`; push with the gh token as a credential helper if needed.

Depth: `AGENTS.md` (operating principles), `SECURITY.md` (claim catalog), `README.md` (operational notes), `CLAUDE.md` (build/test/architecture quick-ref, local-only).
