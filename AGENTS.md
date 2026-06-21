# Operating Principles for RunSecure

For humans and LLMs working on this codebase. README.md tells you *what*; this tells you *why these things are not up for debate*.

If you're an LLM proposing changes to this project, read this file first. The rules below come from incidents that already happened — re-litigating them produces the same incident again.

---

## Architecture decisions that are NOT up for re-litigation

- **No permanent runner daemon.** Self-CI uses the one-shot `infra/scripts/dev/bootstrap-self-runner.sh` script, invoked on demand. A long-running orchestrator wrapper (`while true; do run.sh; sleep 10; done`) was tried, generated continuous `git-credential-manager` and polling noise, and was explicitly retired. Do not propose re-introducing it.
- **Images are terminal.** Don't `FROM ghcr.io/.../runsecure/*` in user Dockerfiles to layer tools on top. The hardening (`apt` removed, root locked, setuid stripped, `/etc` 555) is final. Tools that consumers need go in `tools/*.sh` via the project's `runner.yml`, *before* `finalize-hardening.sh` runs.
- **Versions bump weekly via `weekly-version-bump.yml`.** Don't tag manually unless re-cutting after a bug fix (and even then, prefer triggering `weekly-version-bump.yml` with `bump_type=patch` so the same machinery runs).
- **One approval gate per release.** The `ghcr-publish` environment gates exactly one job (`gate`) in `publish-images.yml`. Don't add `environment: ghcr-publish` to additional jobs — that re-introduces the multi-prompt UX we already fixed.
- **`apt-get upgrade -y` in every Dockerfile is load-bearing.** Without it, grype flags HIGH CVEs in unpatched debian:bookworm-slim packages even on a fresh digest. Don't remove it for "build speed."
- **Python comes from `astral-sh/python-build-standalone`, not Debian.** Debian Bookworm's `python3` is 3.11.2; we ship 3.12. Pinned to a specific release tag + SHA256s per architecture. Adding a new minor version means one new case branch in `images/python.Dockerfile` plus the publish matrix entry.

## 2.1.0 additions — also NOT up for re-litigation

- **GitHub App auth exists** (`internal/auth/githubapp.go`). It is a first-class alternative to PAT auth, selected via `auth_type: github_app` in scope config or `auth.type: github_app` in Helm values. It mints RS256 JWTs, exchanges them for short-lived installation tokens, and caches them. Do not treat it as "future work."
- **Socket-proxy optional mTLS exists** (`internal/config/config.go`; `RUNSECURE_SP_TLS_MODE=mtls`). When enabled, the proxy listens on `:2376`, enforces TLS 1.3, and requires a verified client certificate (`RequireAndVerifyClientCert`). The Helm chart's `tls.enabled` flag wires this up via cert-manager. Default remains `plaintext`.

## Kubernetes backend (2.1.0) — decisions that are NOT up for re-litigation

- **The Kubernetes backend exists (`charts/runsecure-orchestrator/`, `internal/backend/kube/`, `internal/kube/`).** It is not a future plan — it ships in 2.1.0 and is exercised by `tests/integration/k8s/run-k8s-tests.sh`.
- **Runner Pod isolation depends on a NetworkPolicy-enforcing CNI.** Per-spawn `RunnerEgressNetworkPolicy`, `ProxyEgressNetworkPolicy`, and `ProxyIngressNetworkPolicy` are all three created on every spawn. Under kindnet/flannel they are created but silently ignored — the runner can reach the internet directly. Never test security properties on a cluster whose CNI does not enforce NetworkPolicy. The harness uses kind + Calico specifically to avoid this.
- **`ProxyIngressNetworkPolicy` is load-bearing.** Under the namespace default-deny, the runner's `RunnerEgressNetworkPolicy` (egress: allow → proxy:3128) is not enough — the proxy Pod also needs an explicit ingress rule. Without `ProxyIngressNetworkPolicy`, a real CNI blocks runner→proxy:3128. This was a real bug caught during development; do not remove or merge this policy into another one.

## Egress allow-path (2.0.0) — decisions that are NOT up for re-litigation

- **Schema is `http_egress` / `tcp_egress` / `dns`.** `egress.allow_domains` is a deprecated alias (WARNs on both the orchestrator and `run.sh` paths; removed in 3.0). Don't reintroduce it as a primary field. `tcp_egress` ports must be unique and not 80/443; entries are validated (`runneryml.ValidateEgress`, wired into the spawn path).
- **Runner is egress-isolated; only `role=proxy` reaches egress.** The runner attaches to the per-spawn `internal:true` network only — never the `spawn-egress` network or the egress config volume. The socket-proxy enforces this in body-only validation (`ValidateContainerCreate` gates both `NetworkingConfig.EndpointsConfig` and `HostConfig.NetworkMode`, plus the egress volume mount, on `runsecure.role=proxy`). The `/networks/{id}/connect` route is intentionally removed. Don't widen these gates.
- **Per-spawn egress configs are delivered via a shared named volume**, not a tmpfs/host bind. The orchestrator writes to a volume-backed base dir; the proxy reads it read-only via `SQUID_CFG`/`HAPROXY_CFG`/`DNSMASQ_CFG`. A host/tmpfs bind does NOT work on Colima/Docker-Desktop (the daemon can't see another container's tmpfs) — don't "simplify" it back.
- **SSRF guard is operator-gated.** Literal private/special-range IPs in `http_egress`/`tcp_egress` are rejected; Squid also denies private-IP *destinations* (DNS-rebinding defense). A project cannot self-authorize private-range egress — only a scope-level `allow_private_cidrs` override (gated by `allow_project_overrides`) can.
- **A project can't apply an override the scope didn't permit.** Policy resolution is `Defaults(profile)` → scope overrides → per-project overrides gated by `scope.allow_project_overrides`; malformed override values fail the spawn (no silent drop).

## Anti-patterns we've burned ourselves on

- **Pinning locally-built test images by `{{.Id}}`.** That's the config digest, not a manifest digest; `containers/create repo:tag@sha256:<configId>` resolves on Colima but 404s on CI Linux. Integration spawn tests push images through a local `registry:2` and pin by the real `RepoDigest` (production-faithful). Don't revert to `{{.Id}}`.
- **Test PAT permissions.** The orchestrator enforces the PAT file is mode `0400`. In tests it must also be readable by the orchestrator UID (65532) — delivered owned-`65532:0400` via a named volume, not a host bind (uid-remapping differs CI vs Colima). Don't `chmod 444` to "fix" readability (the 0400 check rejects it).
- **Config injection from `runner.yml`.** Every value interpolated into a generated squid/haproxy/dnsmasq config (domains, host:port, wildcards, DNS servers) is sanitized/validated. Don't emit untrusted values into a proxy config unescaped.
- **Build-args that aren't referenced in the install step.** The `ARG PYTHON_VERSION=3.12` → ships 3.11.2 bug (fixed v1.1.5). Every language Dockerfile now has a build-time assertion comparing the installed runtime version to the build-arg. Don't remove those assertions; if you add a new language image, add the equivalent assertion.
- **Broad `--ignore-cve` flags.** Never disable grype's `--fail-on high`. If a finding truly can't be fixed by us (because it's in an upstream-bundled binary), add a *specific* entry to `.grype.yaml` with: the CVE ID, the package, the upstream project, the version that ships the fix, and the trigger that means we can remove the entry. No blanket suppressions.
- **Force-pushing main to "fix" things.** The repo went through a `git-filter-repo` rewrite (May 2026) to scrub Claude/cerebras.net trailers; that's the only legitimate use case. Day-to-day commits go via PRs.
- **AI attribution in commits / PRs / authorship.** No `Co-Authored-By: Claude`, no `🤖 Generated with...` footers, no `cerebras.net` emails. The git history was scrubbed; new commits must not re-introduce it.
- **GitHub `--no-verify` or hook bypasses.** Pre-push validation catches stuff that CI would otherwise reject. Fix the issue, don't skip the check.

## When in doubt

- Security model → `SECURITY.md` (claim catalog with severity, file references, and the acceptance check that verifies each)
- Runtime behavior → `README.md` § "Operational notes"
- Image consumption (tags, lifecycle, verification) → `README.md` § "Consuming RunSecure images"
- Anything else → ask before changing.

## For LLMs specifically

- If a previous session left a redesign document, plan, or scratch file lying around, **verify the premise still holds** before acting on it. The system may have moved on (e.g., the daemon was retired; a "redesign drivers" document still treats it as live).
- Don't propose a new abstraction to solve a problem you haven't reproduced. If grype is "blocking the build," check whether it's actually blocking *now*, not "would block if we approved the gate."
- Read the relevant files end-to-end before editing. Symptoms-from-logs and grep snippets are not enough; bugs in this repo have hidden in unreferenced build-args, dead idempotency checks, and stale environment-mode flags.
