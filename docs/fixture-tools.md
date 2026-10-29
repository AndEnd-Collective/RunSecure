# Native ZIP and SSH fixtures in project runners

Use the existing `apt:` field when quality tests need native archives or local
SSH keys. No additional tool recipe or default package set is required. In the
project's `.github/runner.yml`, select an already promoted RunSecure release:

```yaml
version: "<promoted-release>" # Replace with the chosen X.Y.Z release.
runtime: node:24
apt: [zip, openssh-client]
http_egress: [.github.com, .npmjs.org]
```

`zip` creates archives; the base already includes `unzip`. `openssh-client`
provides `ssh-keygen` and the SSH client utilities. If the project only needs
local key generation and signing, explicitly prune unused client programs:

```yaml
hardening:
  remove: [ssh, scp, sftp, ssh-agent, ssh-add, ssh-keyscan]
```

Keep those removals out of projects that use SSH transport. Installing a client
does not grant network access: the existing egress policy and runtime isolation
still apply. Review the project's actual destinations before adding allowlist
entries; local key generation and ZIP operations need no additional egress.

## Compose from an official release

Use a checkout of the maintained RunSecure composer. A versioned composition
pulls the official terminal image, reads its `io.runsecure.composition-base`
label, validates the official language-build package and digest, and pulls that
exact build-only input. Recipes and the finalizer come from that input. Package
installation happens before terminal hardening removes apt/dpkg functionality,
account helpers, and composition assets. The finished image runs as UID 1001
and carries runtime/full metadata. The temporary root build PATH is restored to
the inherited language PATH, including Cargo when applicable.

```bash
# From the RunSecure checkout; the project config above must contain real X.Y.Z.
set -euo pipefail
PROJECT_IMAGE=$(bash infra/scripts/compose-image.sh /path/to/project | tail -1)
docker image inspect "$PROJECT_IMAGE" --format '{{json .Config.Labels}}'
```

The composer includes its implementation in the project cache key. Updating a
corrected composer therefore cannot silently reuse a project image cached by an
older generation recipe. Terminal release images remain terminal; only the
composer consumes official build-only inputs. Do not layer packages onto a
released runtime image or maintain a separate base fork.

Before publishing, install the repository's checksum-pinned scanners and apply
the same ecosystem-aware fixed HIGH/CRITICAL gate used in image CI:

```bash
infra/scripts/install-pinned-scanners.sh /path/to/task-local/bin
# Put that directory on PATH, then scan the composed image.
bash infra/scripts/grype-scan-image.sh "docker:$PROJECT_IMAGE" \
  composed-image.sarif zip javascript-package-cataloger npm
bash tests/validation/test-scanner-package-inventory.sh \
  "$PROJECT_IMAGE" openssh-client
```

The blocking SBOM retains dpkg, npm, Python, Go, Cargo, and .NET catalogers and
checks the requested package inventory. Retain SARIF and build provenance;
do not disable the fixed HIGH/CRITICAL gate or add blanket suppressions.

Publish the validated project image to the operator's registry, then resolve its
**registry manifest digest**. A local `docker inspect .Id` is a config digest and
must never be used as a deployment image pin. For example:

```bash
PROJECT_REF=registry.example.com/ci/quality:validated-build
PROJECT_REPOSITORY=registry.example.com/ci/quality
docker tag "$PROJECT_IMAGE" "$PROJECT_REF"
docker push "$PROJECT_REF"
MANIFEST_DIGEST=$(docker buildx imagetools inspect "$PROJECT_REF" \
  --format '{{.Manifest.Digest}}')
printf '%s@%s\n' "$PROJECT_REPOSITORY" "$MANIFEST_DIGEST"
```

Record the official release manifest, source revision, builder digest, project
configuration, scanner evidence, supported platform, and final registry digest.
Verify the pushed digest and architecture before switching a deployment to it.
A successful local fixture probe alone does not establish release acceptance or
production readiness.

## Put large fixtures in the job workspace

The Compose Go backend keeps `/tmp` at 512 MiB with `noexec,nosuid,nodev`.
Large test fixtures belong under the writable job workspace. Set `TMPDIR` for
the process that owns those fixtures, create the directory first, and remove it
when the process exits. A workflow step can use:

```yaml
- name: Run project quality tests
  shell: bash
  run: |
    set -euo pipefail
    export TMPDIR="$RUNNER_TEMP/defense-quality"
    mkdir -p "$TMPDIR"
    trap 'rm -rf "$TMPDIR"' EXIT
    npm run quality # Replace with the project's full quality command.
```

A child launched with a filtered environment may not inherit `TMPDIR`. Pass it
through that child's explicit environment if it creates these fixtures. Confirm
where the fixture-owning process actually writes; setting a parent variable
does not move every process's temporary files. Do not enlarge or make `/tmp`
executable to compensate for a missing native tool or a fixture path mistake.

## Deploy and verify

Keep operator state outside the source checkout. Capture the current image
pins and scope configuration before changing them. For Compose, set the matching
`RUNSECURE_RUNNER_IMAGE_NODE` or default image to the composed registry digest
and add only that validated terminal digest to the existing operator extra-image
allowlist file. Build-only image digests must never enter the runtime allowlist.
Keep the orchestrator, proxy, and socket-proxy on matching official release
manifest pins. Follow [the Compose install guide](../install.md) or
[the Kubernetes install guide](../install-kubernetes.md) for backend-specific
configuration and credentials.

Coordinate an idle window for rollout. Stop the controller gracefully to stop
new admissions and allow active jobs to drain; Compose already provides a
90-second stop grace for the default 60-second drain and bounded cleanup.
Allow longer-running jobs to finish before requesting stop. Restart through the
tracked deployment wrapper with the new pin. Do not run a second controller for
the same scope during the switch.

Require `/healthz` and `/readyz` to succeed, inspect state and recent spawn errors,
and verify the actual spawned image digest and security posture. Then run the
project's **full real quality workflow**, including native ZIP roundtrip, SSH
key/signature fixtures, runtime version checks, and the existing egress-denial
checks. Record the GitHub run, all check results, and available remote job logs.
A container starting or a reduced smoke command passing is insufficient.

After completion, verify that ephemeral runners are removed from GitHub, the
per-spawn runner/proxy resources are gone, and in-flight state returns to zero.
The release live-acceptance gate remains required for official promotion; this
project-specific probe does not replace it.

On failure, preserve logs and the exact failing digest. Drain or stop the new
controller, restore the captured configuration and previous known-good digest
pins, and restart through the same wrapper. Confirm readiness and one real job
on the restored configuration. Cold-start reconciliation handles only exactly
owned backend resources and offline runner registrations and fails closed when
ownership or cleanup cannot be proven. Investigate unresolved cleanup debt
before reopening admission; never delete other scopes' resources or loosen the
runtime allowlist to recover.
