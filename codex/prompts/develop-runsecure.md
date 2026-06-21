Work on the RunSecure codebase (hardened, ephemeral, egress-controlled GitHub Actions runners). Read `AGENTS.md` first — its architecture decisions and anti-patterns came from real incidents; do not re-litigate them.

Architecture (build bottom-up): `debian:bookworm-slim` (digest-pinned) → `runner-base` → `runner-{node,python,rust}:<ver>` → optional project image (`compose-image.sh` layers `tools/*.sh` then `finalize-hardening.sh`). Runtime (orchestrator, Compose backend): distroless Go `orchestrator` → `socket-proxy` (only thing mounting docker.sock; strict body validation) spawns a per-job combined proxy (squid+haproxy+dnsmasq) + runner. Runner is on an `internal:true` network only; proxy is dual-homed to a deploy-provisioned `spawn-egress` network and enforces the `runner.yml` allowlist at L7. Per-spawn egress configs reach the proxy via a shared named volume. Backend abstraction: `internal/backend/backend.go` defines the `Backend` interface; `internal/backend/compose/` and `internal/backend/kube/` are the two implementations. Kubernetes backend (`backend: kube`): per-spawn runner Pod + proxy Pod + ClusterIP Service + three NetworkPolicies (all load-bearing under a CNI enforcing NetworkPolicy; see `AGENTS.md`) + Secret (GC owner) in a per-scope namespace; runner.yml fetched via GitHub API. `internal/kube/`: object builders + client (used only by the kube backend). `internal/auth/`: PAT provider (`pat.go`) and GitHub App provider (`githubapp.go` — RS256 JWT minting, installation token caching). Socket-proxy optional mTLS (`internal/config/config.go`; `RUNSECURE_SP_TLS_MODE=mtls`; TLS 1.3, `RequireAndVerifyClientCert`; wired via `tls.enabled` in the Helm chart).

Hard rules:
- No AI attribution in commits/PRs/authorship. Never commit to `main` — branch + PR; commit after each change cycle. `CLAUDE.md`/`.claude/` are gitignored by design.
- Never weaken security: keep `grype --fail-on high --only-fixed`; unfixable upstream-bundled CVEs get a specific justified `.grype.yaml` entry (id + package + upstream + fix version + removal trigger), never a blanket suppression. Keep socket-proxy egress/volume/image gates + runner egress-isolation (only `role=proxy` attaches the egress network/volume). A project can't self-authorize an override the scope didn't permit.
- Pin + assert: digest/version-pin everything (ARGs + checksums, image digests, GH Action SHAs); each language image asserts the installed runtime matches its build-arg; `apt-get upgrade -y` stays in every Dockerfile.
- TDD + ≥95% coverage on the Go modules; behavioral changes ship positive + negative + attacker tests; sanitize every value interpolated into a generated proxy config.
- Read files end-to-end before editing — bugs hide in unreferenced build-args, dead idempotency checks, stale env-mode flags.

Commands:
- Images: `docker build -f images/base.Dockerfile -t runner-base:latest .`
- Go: `cd infra/orchestrator && go test ./... -cover`; `cd infra/socket-proxy && go test ./... -cover` (+ FuzzValidateContainerCreate)
- Coverage gate (logic pkgs ≥99%): `bash tests/validation/test-go-coverage.sh`
- Host lints: `for t in tests/validation/test-*.sh; do bash "$t"; done`
- Integration (Docker): `./tests/integration/run-integration-tests.sh [--test <suite>]` (spawn suites push test images through a local `registry:2` for real manifest digests; PAT delivered at mode 0400 via named volume)
- Kubernetes integration: `./tests/integration/k8s/run-k8s-tests.sh` (kind + Calico; CNI must enforce NetworkPolicy)

Adding a language/version or tool means updating ALL matrices (`publish-images.yml`, `post-publish-acceptance.yml`, `promote-to-stable.yml`) + acceptance claims. Adding a backend, auth provider, or kube object: follow the `internal/backend/`, `internal/auth/`, `internal/kube/` patterns and ship positive + negative + attacker tests. Release: trigger `weekly-version-bump.yml` (`bump_type`; runs `go get -u` on both modules) → publish (canary) → acceptance → promote (re-runs coverage gate). Self-CI: `infra/scripts/dev/bootstrap-self-runner.sh` to clear `lints-on-self`, then kill it.

Verify by running the actual commands and reporting output; build + Grype-scan any Dockerfile/pin change. Depth: `AGENTS.md`, `SECURITY.md`, `README.md`, `CLAUDE.md`.
