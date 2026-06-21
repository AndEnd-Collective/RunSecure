Work on the RunSecure codebase (hardened, ephemeral, egress-controlled GitHub Actions runners). Read `AGENTS.md` first — its architecture decisions and anti-patterns came from real incidents; do not re-litigate them.

Architecture (build bottom-up): `debian:bookworm-slim` (digest-pinned) → `runner-base` → `runner-{node,python,rust}:<ver>` → optional project image (`compose-image.sh` layers `tools/*.sh` then `finalize-hardening.sh`). Runtime (orchestrator, Compose backend): distroless Go `orchestrator` → `socket-proxy` (only thing mounting docker.sock; strict body validation) spawns a per-job combined proxy (squid+haproxy+dnsmasq) + runner. Runner is on an `internal:true` network only; proxy is dual-homed to a deploy-provisioned `spawn-egress` network and enforces the `runner.yml` allowlist at L7. Per-spawn egress configs reach the proxy via a shared named volume. Kubernetes backend (`backend: kube`): per-spawn runner Pod + proxy Pod + ClusterIP Service + per-spawn NetworkPolicies + Secret (GC owner); runner.yml fetched via GitHub API rather than bind-mount.

Hard rules:
- No AI attribution in commits/PRs/authorship. Never commit to `main` — branch + PR; commit after each change cycle. `CLAUDE.md`/`.claude/` are gitignored by design.
- Never weaken security: keep `grype --fail-on high --only-fixed`; unfixable upstream-bundled CVEs get a specific justified `.grype.yaml` entry (id + package + upstream + fix version + removal trigger), never a blanket suppression. Keep socket-proxy egress/volume/image gates + runner egress-isolation (only `role=proxy` attaches the egress network/volume). A project can't self-authorize an override the scope didn't permit.
- Pin + assert: digest/version-pin everything (ARGs + checksums, image digests, GH Action SHAs); each language image asserts the installed runtime matches its build-arg; `apt-get upgrade -y` stays in every Dockerfile.
- TDD + ≥95% coverage on the Go modules; behavioral changes ship positive + negative + attacker tests; sanitize every value interpolated into a generated proxy config.
- Read files end-to-end before editing — bugs hide in unreferenced build-args, dead idempotency checks, stale env-mode flags.

Commands:
- Images: `docker build -f images/base.Dockerfile -t runner-base:latest .`
- Go: `cd infra/orchestrator && go test ./... -cover`; `cd infra/socket-proxy && go test ./... -cover` (+ FuzzValidateContainerCreate)
- Host lints: `for t in tests/validation/test-*.sh; do bash "$t"; done`
- Integration (Docker): `./tests/integration/run-integration-tests.sh [--test <suite>]` (spawn suites push test images through a local `registry:2` for real manifest digests; PAT delivered at mode 0400 via named volume)

Adding a language/version or tool means updating ALL matrices (`publish-images.yml`, `post-publish-acceptance.yml`, `promote-to-stable.yml`) + acceptance claims. Release: trigger `weekly-version-bump.yml` (`bump_type`) → publish (canary) → acceptance → promote. Self-CI: `infra/scripts/dev/bootstrap-self-runner.sh` to clear `lints-on-self`, then kill it.

Verify by running the actual commands and reporting output; build + Grype-scan any Dockerfile/pin change. Depth: `AGENTS.md`, `SECURITY.md`, `README.md`, `CLAUDE.md`.
