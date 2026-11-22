# Supply-chain status

This directory is RunSecure's published account of what it is built from and
what is known to be wrong with it. Most of it is generated every night; two
files are written by hand and are the policy the rest is checked against.

| File | Written by | What it is |
|---|---|---|
| [STATUS.md](STATUS.md) | Generated nightly | The summary: dependency counts per module, open and assessed advisories, pinned components |
| [dependencies.md](dependencies.md) | Generated nightly | Every dependency of every module, how far it is from our code, and which upstream owns it |
| [vulnerabilities.json](vulnerabilities.json) | Generated nightly | Every advisory match, machine-readable |
| [sbom/](sbom) | Generated nightly | One CycloneDX SBOM per Go module |
| [upstreams.yml](upstreams.yml) | Maintainers | The registry of every upstream we rely on, and why it is trusted |
| [assessments.yml](assessments.yml) | Maintainers | Reviewed conclusions about individual advisory matches |

The generated files change only when the facts change. To see when the check
last ran, look at the
[security-status workflow runs](https://github.com/AndEnd-Collective/RunSecure/actions/workflows/security-status.yml).

## How it is produced

Every night [`security-status.yml`](../.github/workflows/security-status.yml):

1. runs [cdxgen](https://github.com/cdxgen/cdxgen) on each Go module to produce
   a CycloneDX SBOM with its dependency graph;
2. runs [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) on each
   SBOM to match it against known advisories;
3. runs `infra/scripts/security-status.py`, which joins those results with
   `upstreams.yml` and `assessments.yml` and writes the files above;
4. if anything changed, opens a pull request that is merged automatically once
   CI is green.

To regenerate locally (needs `cdxgen`, `depscan`, `go`, `jq` and PyYAML; the
first run downloads dep-scan's application database, about 4.5 GB):

```bash
./infra/scripts/generate-security-status.sh
```

## Dependency policy

RunSecure depends only on software from upstreams that are widely used,
actively maintained, and publish security advisories: the Go project,
Kubernetes and its SIGs, OpenTelemetry, Debian, GitHub's own runner and CLI,
the official language toolchains, and a small number of long-established
libraries that those pull in.

This is enforced, not just stated:

- **Every Go module named in any `go.mod`, direct or indirect, must match an
  entry in [upstreams.yml](upstreams.yml).** The test suite
  (`tests/validation/test-security-status.sh`) fails otherwise. A dependency
  from a new upstream cannot arrive unnoticed in a refresh; someone has to add
  the upstream to the registry and say why it is trusted.
- **Every version pin in a Dockerfile that brings in third-party software is
  listed under `pinned_components`**, with the upstream that owns it.
- **Downloads are pinned and verified.** Base images are pinned by digest;
  release artifacts (runner, GitHub CLI, npm, CPython, Helm, yq and the rest)
  are pinned by version and checked against a SHA-256.

The dependency sets are small on purpose. `STATUS.md` shows the count per
module; `dependencies.md` lists each one.

### Reading the distances

Our own code is the first party. In `dependencies.md` and `STATUS.md`:

| Term | Meaning |
|---|---|
| Third party (direct) | A module our code imports itself |
| Fourth party | A module that one of our direct dependencies imports |
| Depth N | Further still; the "Reached through" column shows the chain |

Most of what we depend on is fourth party: it arrives because Kubernetes
client-go or the OpenTelemetry collector API needs it, not because we chose
it. That is why the registry records the upstream for those too.

## When an advisory appears

### What a row under "Open advisories" means

dep-scan matches advisories by package name and version. A row under **Open
advisories** means: an advisory names a package and version that is in one of
our dependency graphs, and nobody has assessed it yet. It does not yet mean
RunSecure is exploitable. Three things can be true:

| Situation | What happens |
|---|---|
| A fixed version exists | Dependabot opens a pull request. [`security-response.yml`](../.github/workflows/security-response.yml) merges it when CI is green and starts a nightly build immediately. The row disappears on the next run. |
| No fixed version exists | The same workflow runs an impact analysis against the repository and records it on an [issue labelled `security-advisory`](https://github.com/AndEnd-Collective/RunSecure/issues?q=is%3Aissue+label%3Asecurity-advisory): whether the vulnerable code is built, whether it can be reached, and by whom. |
| The match is wrong, or right but irrelevant | A maintainer records the conclusion in [assessments.yml](assessments.yml), with a reference. The row moves to **Assessed advisories**; it is never deleted. |

### Finding where in the upstream the problem is

Each advisory row answers the three questions needed to follow it upstream:

1. **Which package, and how it reaches us.** The "How it reaches us" column is
   the import chain from our module to the affected package. If the chain has
   more than one step, the fix usually has to be released by the package
   *and* picked up by the module in between.
2. **Who has to fix it.** The "Upstream that fixes it" column links the
   upstream's issue tracker, taken from `upstreams.yml`.
3. **What to do meanwhile.** The dep-scan guidance column carries the fixed
   version when one exists.

For software that is not a Go module (the runner, the GitHub CLI, npm, the
language toolchains, Debian packages), the route is the **Pinned components**
table: it names the pin that controls the version and the upstream that ships
it. Advisories in those surface through the image scans described below, and
the fix is a pin bump once the upstream releases.

## The other layers

This directory covers the Go modules RunSecure builds and the components it
pins. It is one of several checks, and not the one that gates a release:

| Layer | What it covers | Effect |
|---|---|---|
| Grype scan of every image | Operating system packages and everything bundled in each published image, both architectures | **Gates the release.** A fixable HIGH or CRITICAL fails the publish; `nightly` and stable tags do not move. Exceptions live in [`.grype.yaml`](../.grype.yaml), each with the upstream, the pin, a reachability rationale and a removal trigger. |
| Build provenance | Every published image | Signed attestation that the image was built by this repository's publish workflow from a given commit; verified before any tag moves. See the main [README](../README.md#verify-what-you-pull). |
| Dependabot | Every manifest in the repository, including test-only dependencies that are not compiled into anything shipped | Opens the fix when one exists. |
| OWASP dep-scan (this directory) | Go modules that are compiled into what we ship, with their full dependency graph | Publishes the status; feeds triage. |
| Post-publish acceptance | The published images, by digest | Checks the documented hardening claims against the real artifacts before promotion. |

Two limits worth knowing:

- A module that consists only of tests compiles no third-party code into
  anything we ship, so its SBOM is empty here. Its `go.mod` is still watched by
  Dependabot.
- The image contents (Debian packages, the runner's bundled runtimes) are not
  listed in this directory. They are inventoried and scanned at build time by
  Syft and Grype, and that scan is the release gate.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Please do not open a public issue for an
undisclosed vulnerability in RunSecure itself.
