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

## Anti-patterns we've burned ourselves on

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
