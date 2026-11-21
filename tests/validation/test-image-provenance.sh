#!/bin/bash
# ============================================================================
# RunSecure — every published image is attested, and no tag moves without it
# ============================================================================
# Published images used to carry nothing that tied them to this repository:
# no signature, no provenance. A consumer could not tell a RunSecure image
# from a look-alike, and promotion trusted whatever digest the manifest named.
#
# Asserts:
#   - every build step in publish-images.yml is followed by a provenance
#     attestation bound to that step's own digest and image, pushed to the
#     registry, with the permissions keyless signing needs;
#   - the `nightly` retag and the stable promotion both verify provenance
#     first, in the same step sequence, with no way to skip it;
#   - verify-image-provenance.sh demands the signer workflow, source ref and
#     commit for every image, and one failure fails the run.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PUBLISH="${RUNSECURE_ROOT}/.github/workflows/publish-images.yml"
PROMOTE="${RUNSECURE_ROOT}/.github/workflows/promote-to-stable.yml"
VERIFIER="${RUNSECURE_ROOT}/infra/scripts/verify-image-provenance.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-provenance-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT

python3 - "$PUBLISH" "$PROMOTE" <<'PY'
import pathlib
import re
import sys
import yaml

publish = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
promote = yaml.safe_load(pathlib.Path(sys.argv[2]).read_text())
jobs = publish["jobs"]
PREFIX = "${{ env.IMAGE_PREFIX }}"

# job -> {build step id: image the step pushes}
expected = {
    "base": {"build": f"{PREFIX}/base"},
    "languages": {
        "build-stage": f"{PREFIX}/${{{{ matrix.name }}}}-build",
        "build": f"{PREFIX}/${{{{ matrix.name }}}}",
    },
    "proxy": {"build": f"{PREFIX}/proxy"},
    "orchestrator": {"build": f"{PREFIX}/orchestrator"},
    "socket-proxy": {"build": f"{PREFIX}/socket-proxy"},
}
build_jobs = {
    name
    for name, job in jobs.items()
    if any("docker/build-push-action@" in step.get("uses", "") for step in job["steps"])
}
assert build_jobs == set(expected), f"build jobs changed: {sorted(build_jobs)}"

for name, images in expected.items():
    job = jobs[name]
    permissions = job["permissions"]
    assert permissions.get("id-token") == "write", f"{name}: keyless signing needs id-token: write"
    assert permissions.get("attestations") == "write", f"{name}: needs attestations: write"
    steps = job["steps"]
    attests = [step for step in steps if "actions/attest-build-provenance@" in step.get("uses", "")]
    assert len(attests) == len(images), f"{name}: {len(attests)} attestations for {len(images)} builds"
    seen = set()
    for step in attests:
        assert re.fullmatch(r"actions/attest-build-provenance@[0-9a-f]{40}", step["uses"]), step["uses"]
        assert "if" not in step and "continue-on-error" not in step, f"{name}: attestation can be skipped"
        with_ = step["with"]
        match = re.fullmatch(r"\$\{\{ steps\.([a-z-]+)\.outputs\.digest \}\}", with_["subject-digest"])
        assert match, f"{name}: attestation is not bound to a build step's digest"
        build_id = match.group(1)
        assert images.get(build_id) == with_["subject-name"], (
            f"{name}: digest of step '{build_id}' attested under {with_['subject-name']}"
        )
        assert with_["push-to-registry"] is True
        build_index = next(i for i, s in enumerate(steps) if s.get("id") == build_id)
        assert steps.index(step) > build_index, f"{name}: attestation precedes its build"
        seen.add(build_id)
    assert seen == set(images), f"{name}: unattested build steps {sorted(set(images) - seen)}"


def verify_then(job, later, where):
    """The provenance check must come before `later` and must not be skippable."""
    steps = job["steps"]
    verify = [i for i, s in enumerate(steps) if "verify-image-provenance.sh" in s.get("run", "")]
    act = [i for i, s in enumerate(steps) if later in s.get("run", "")]
    assert len(verify) == 1 and len(act) == 1, f"{where}: expected one verify and one '{later}'"
    assert verify[0] <= act[0], f"{where}: tags move before provenance is verified"
    step = steps[verify[0]]
    assert "if" not in step and "continue-on-error" not in step, f"{where}: verification can be skipped"
    run = step["run"]
    assert run.index("verify-image-provenance.sh") < run.index(later) if later in run else True
    assert "|| true" not in run
    assert job["permissions"].get("attestations") == "read", f"{where}: needs attestations: read"
    return step


nightly = verify_then(jobs["nightly"], "tag-nightly-images.py", "nightly")
assert nightly["env"]["SOURCE_REF"] == "${{ github.ref }}"
assert nightly["env"]["BUILD_SHA"] == "${{ github.sha }}"

stable = verify_then(promote["jobs"]["promote"], "promote-release-images.py", "promote")
assert '"refs/tags/v${VERSION}" "$BUILD_SHA"' in stable["run"]
PY

digest_a="sha256:$(printf 'a%.0s' {1..64})"
digest_b="sha256:$(printf 'b%.0s' {1..64})"
prefix="ghcr.io/andend-collective/runsecure"
sha="$(printf 'c%.0s' {1..40})"
cat > "${tmp}/manifest.json" <<EOF
{"images": {"base": "${prefix}/base@${digest_a}", "proxy": "${prefix}/proxy@${digest_b}"}}
EOF

# The stub records every invocation and fails for references listed in
# $STUB_REJECT.
mkdir -p "${tmp}/bin"
cat > "${tmp}/bin/gh" <<'STUB'
#!/bin/bash
echo "$*" >> "${STUB_LOG}"
for rejected in ${STUB_REJECT:-}; do
  [[ "$3" == "oci://${rejected}" ]] && exit 1
done
exit 0
STUB
chmod +x "${tmp}/bin/gh"

run_verifier() {
  : > "${tmp}/log"
  env PATH="${tmp}/bin:${PATH}" STUB_LOG="${tmp}/log" "$@"
}

if ! run_verifier bash "$VERIFIER" "${tmp}/manifest.json" AndEnd-Collective/RunSecure refs/tags/v9.9.9 "$sha" > "${tmp}/ok.out" 2>&1; then
  echo "FAIL: verifier rejected images that all have provenance: $(tail -2 "${tmp}/ok.out")" >&2
  exit 1
fi
if [[ "$(wc -l < "${tmp}/log" | tr -d ' ')" != "2" ]]; then
  echo "FAIL: verifier did not check every image: $(cat "${tmp}/log")" >&2
  exit 1
fi
for required in \
  "attestation verify oci://${prefix}/base@${digest_a}" \
  "attestation verify oci://${prefix}/proxy@${digest_b}" \
  "--repo AndEnd-Collective/RunSecure" \
  "--signer-workflow AndEnd-Collective/RunSecure/.github/workflows/publish-images.yml" \
  "--source-ref refs/tags/v9.9.9" \
  "--source-digest ${sha}" \
  "--deny-self-hosted-runners"; do
  if ! grep -qF -- "$required" "${tmp}/log"; then
    echo "FAIL: verifier does not enforce '${required}'" >&2
    exit 1
  fi
done

if run_verifier env STUB_REJECT="${prefix}/proxy@${digest_b}" \
    bash "$VERIFIER" "${tmp}/manifest.json" AndEnd-Collective/RunSecure refs/heads/main "$sha" > "${tmp}/bad.out" 2>&1; then
  echo "FAIL: verifier passed although one image has no provenance" >&2
  exit 1
fi
if ! grep -qF "1 of 2 images failed provenance verification" "${tmp}/bad.out"; then
  echo "FAIL: verifier failed without naming the unattested image: $(tail -2 "${tmp}/bad.out")" >&2
  exit 1
fi

# expect_refused NAME ARGS...
expect_refused() {
  local name="$1"
  shift
  if run_verifier bash "$VERIFIER" "$@" > "${tmp}/refused.out" 2>&1; then
    echo "FAIL: ${name} was accepted" >&2
    exit 1
  fi
  if [[ -s "${tmp}/log" ]]; then
    echo "FAIL: ${name} reached gh before being refused" >&2
    exit 1
  fi
}
printf '{"images": {"base": "%s/base:3.0.0"}}\n' "$prefix" > "${tmp}/mutable.json"
printf '{"images": {}}\n' > "${tmp}/empty.json"
expect_refused "a mutable tag reference" "${tmp}/mutable.json" AndEnd-Collective/RunSecure refs/tags/v9.9.9 "$sha"
expect_refused "an empty manifest" "${tmp}/empty.json" AndEnd-Collective/RunSecure refs/tags/v9.9.9 "$sha"
expect_refused "a branch other than main" "${tmp}/manifest.json" AndEnd-Collective/RunSecure refs/heads/feature "$sha"
expect_refused "a non-release tag" "${tmp}/manifest.json" AndEnd-Collective/RunSecure refs/tags/v9.9.9-rc1 "$sha"
expect_refused "a malformed commit" "${tmp}/manifest.json" AndEnd-Collective/RunSecure refs/tags/v9.9.9 "not-a-sha"

echo "PASS: every build is attested by digest, and nightly and stable tags move only after provenance verifies"
