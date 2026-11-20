#!/bin/bash
# ============================================================================
# RunSecure — `nightly` moves only after every Grype scan has passed
# ============================================================================
# publish-images.yml used to push `nightly` in the same step as
# `<version>-canary`, before any scan ran. A release whose scan then failed
# (v2.2.3 and v2.2.4 both did) still moved `nightly`, so the tag people pull
# without pinning pointed at images that had failed the gate.
#
# Asserts:
#   - no build step tags `nightly`
#   - one job retags `nightly`, it needs every scan job and the release
#     manifest, and it only runs for tag pushes (a manual build from a branch
#     must not move it)
#   - tag-nightly-images.py maps manifest entries to the documented tags,
#     retags by digest, and rejects anything that is not a RunSecure digest
#     reference
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/publish-images.yml"
TAGGER="${RUNSECURE_ROOT}/infra/scripts/tag-nightly-images.py"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-nightly-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT

python3 - "$WORKFLOW" <<'PY'
import pathlib
import sys
import yaml

workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
jobs = workflow["jobs"]

build_steps = [
    (name, step)
    for name, job in jobs.items()
    for step in job["steps"]
    if "docker/build-push-action@" in step.get("uses", "")
]
assert build_steps, "no build steps found"
for name, step in build_steps:
    tags = step["with"].get("tags", "")
    assert "nightly" not in tags, f"{name}: a build step still tags nightly: {tags!r}"
    assert "-canary" in tags, f"{name}: build step lost its canary tag"

scan_jobs = {name for name in jobs if name.startswith("grype-scan")}
assert len(scan_jobs) == 6, scan_jobs

taggers = [
    name
    for name, job in jobs.items()
    if any("tag-nightly-images.py" in step.get("run", "") for step in job["steps"])
]
assert taggers == ["nightly"], taggers
nightly = jobs["nightly"]
needs = set(nightly["needs"])
assert scan_jobs <= needs, f"nightly does not wait for: {sorted(scan_jobs - needs)}"
assert "release-manifest" in needs
assert nightly["if"] == "github.event_name == 'push'", nightly.get("if")
assert nightly["permissions"] == {"actions": "read", "contents": "read", "packages": "write"}
for step in nightly["steps"]:
    assert "continue-on-error" not in step
    assert "always()" not in str(step.get("if", ""))
PY

digest_a="sha256:$(printf 'a%.0s' {1..64})"
digest_b="sha256:$(printf 'b%.0s' {1..64})"
prefix="ghcr.io/andend-collective/runsecure"
cat > "${tmp}/manifest.json" <<EOF
{
  "schema_version": 2,
  "release": "9.9.9",
  "images": {
    "base": "${prefix}/base@${digest_a}",
    "node-24": "${prefix}/node@${digest_a}",
    "node-build-24": "${prefix}/node-build@${digest_b}",
    "orchestrator": "${prefix}/orchestrator@${digest_a}",
    "proxy": "${prefix}/proxy@${digest_a}",
    "python-3.12": "${prefix}/python@${digest_a}",
    "python-build-3.12": "${prefix}/python-build@${digest_b}",
    "rust-build-stable": "${prefix}/rust-build@${digest_b}",
    "rust-stable": "${prefix}/rust@${digest_a}",
    "socket-proxy": "${prefix}/socket-proxy@${digest_a}"
  }
}
EOF
cat > "${tmp}/expected.txt" <<EOF
${prefix}/base:nightly ${prefix}/base@${digest_a}
${prefix}/node:nightly-24 ${prefix}/node@${digest_a}
${prefix}/node-build:nightly-24 ${prefix}/node-build@${digest_b}
${prefix}/orchestrator:nightly ${prefix}/orchestrator@${digest_a}
${prefix}/proxy:nightly ${prefix}/proxy@${digest_a}
${prefix}/python:nightly-3.12 ${prefix}/python@${digest_a}
${prefix}/python-build:nightly-3.12 ${prefix}/python-build@${digest_b}
${prefix}/rust-build:nightly-stable ${prefix}/rust-build@${digest_b}
${prefix}/rust:nightly-stable ${prefix}/rust@${digest_a}
${prefix}/socket-proxy:nightly ${prefix}/socket-proxy@${digest_a}
EOF
python3 "$TAGGER" --print "${tmp}/manifest.json" > "${tmp}/actual.txt"
if ! diff -u "${tmp}/expected.txt" "${tmp}/actual.txt"; then
  echo "FAIL: nightly tag plan differs from the documented mapping" >&2
  exit 1
fi

# expect_rejected NAME IMAGES_JSON
expect_rejected() {
  local name="$1"
  printf '{"images": %s}\n' "$2" > "${tmp}/bad.json"
  if python3 "$TAGGER" --print "${tmp}/bad.json" > "${tmp}/bad.out" 2>&1; then
    echo "FAIL: ${name} was accepted: $(cat "${tmp}/bad.out")" >&2
    exit 1
  fi
  if ! grep -q '^nightly tag error:' "${tmp}/bad.out"; then
    echo "FAIL: ${name} failed without a nightly tag error: $(cat "${tmp}/bad.out")" >&2
    exit 1
  fi
}
expect_rejected "a mutable tag reference" "{\"base\": \"${prefix}/base:2.2.2-canary\"}"
expect_rejected "an image outside the RunSecure registry path" "{\"base\": \"ghcr.io/someone-else/base@${digest_a}\"}"
expect_rejected "a key that does not belong to its package" "{\"node-24\": \"${prefix}/python@${digest_a}\"}"
expect_rejected "a variant that would inject a second tag" "{\"node-24,latest\": \"${prefix}/node@${digest_a}\"}"
expect_rejected "an empty manifest" "{}"

echo "PASS: nightly is retagged by digest only after every scan job, and only for tag pushes"
