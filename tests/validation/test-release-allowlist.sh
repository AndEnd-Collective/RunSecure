#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GENERATOR="${RUNSECURE_ROOT}/infra/socket-proxy/generate-release-allowlist.sh"
MANIFEST_GENERATOR="${RUNSECURE_ROOT}/infra/scripts/generate-release-manifest.py"
PUBLISH_WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/publish-images.yml"
WEEKLY_WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/weekly-version-bump.yml"
PROMOTE_WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/promote-to-stable.yml"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

digest() {
  local character=$1
  printf '%64s' '' | tr ' ' "$character"
}

cat > "${tmp}/all.txt" <<EOF
ghcr.io/andend-collective/runsecure/proxy@sha256:$(digest a)
ghcr.io/andend-collective/runsecure/node@sha256:$(digest b)
ghcr.io/andend-collective/runsecure/node@sha256:$(digest c)
ghcr.io/andend-collective/runsecure/python@sha256:$(digest d)
ghcr.io/andend-collective/runsecure/rust@sha256:$(digest e)
EOF

"$GENERATOR" "${tmp}/allowed-images.txt" "${tmp}/all.txt"

if [[ $(grep -c '^ghcr.io/' "${tmp}/allowed-images.txt") -ne 5 ]]; then
  echo "FAIL: generated allowlist did not preserve all five immutable manifests" >&2
  exit 1
fi
for package in proxy node python rust; do
  if ! grep -q "runsecure/${package}@sha256:" "${tmp}/allowed-images.txt"; then
    echo "FAIL: generated allowlist is missing $package" >&2
    exit 1
  fi
done

grep -v '/rust@' "${tmp}/all.txt" > "${tmp}/missing-rust.txt"
if "$GENERATOR" "${tmp}/must-not-exist.txt" "${tmp}/missing-rust.txt" 2>/dev/null; then
  echo "FAIL: generator accepted an allowlist without rust" >&2
  exit 1
fi

sed 's@/node@/runner-node@' "${tmp}/all.txt" > "${tmp}/wrong-package.txt"
if "$GENERATOR" "${tmp}/must-not-exist.txt" "${tmp}/wrong-package.txt" 2>/dev/null; then
  echo "FAIL: generator accepted the obsolete runner-node package name" >&2
  exit 1
fi

cat > "${tmp}/release-digest-proxy.txt" <<EOF
ghcr.io/andend-collective/runsecure/proxy@sha256:$(digest a)
EOF
cat > "${tmp}/release-digest-node-24.txt" <<EOF
ghcr.io/andend-collective/runsecure/node@sha256:$(digest b)
EOF
cat > "${tmp}/release-digest-node-22.txt" <<EOF
ghcr.io/andend-collective/runsecure/node@sha256:$(digest c)
EOF
cat > "${tmp}/release-digest-python-3.12.txt" <<EOF
ghcr.io/andend-collective/runsecure/python@sha256:$(digest d)
EOF
cat > "${tmp}/release-digest-rust-stable.txt" <<EOF
ghcr.io/andend-collective/runsecure/rust@sha256:$(digest e)
EOF
cat > "${tmp}/release-digest-orchestrator.txt" <<EOF
ghcr.io/andend-collective/runsecure/orchestrator@sha256:$(digest f)
EOF
cat > "${tmp}/release-digest-socket-proxy.txt" <<EOF
ghcr.io/andend-collective/runsecure/socket-proxy@sha256:$(digest 0)
EOF

python3 "$MANIFEST_GENERATOR" \
  --release 2.1.8 \
  --build-sha "$(digest 1 | cut -c1-40)" \
  --output "${tmp}/release-images.json" \
  "${tmp}"/release-digest-*.txt

python3 - "${tmp}/release-images.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema_version"] == 1
assert manifest["release"] == "2.1.8"
assert set(manifest["images"]) == {
    "node-22",
    "node-24",
    "orchestrator",
    "proxy",
    "python-3.12",
    "rust-stable",
    "socket-proxy",
}
assert "runsecure/orchestrator@sha256:" in manifest["images"]["orchestrator"]
assert "runsecure/socket-proxy@sha256:" in manifest["images"]["socket-proxy"]
PY

if python3 "$MANIFEST_GENERATOR" \
    --release 2.1.8 \
    --build-sha "$(digest 1 | cut -c1-40)" \
    --output "${tmp}/must-not-exist.json" \
    "${tmp}"/release-digest-node-*.txt \
    "${tmp}"/release-digest-orchestrator.txt \
    "${tmp}"/release-digest-proxy.txt \
    "${tmp}"/release-digest-python-3.12.txt \
    "${tmp}"/release-digest-rust-stable.txt 2>/dev/null; then
  echo "FAIL: release manifest accepted a missing socket-proxy digest" >&2
  exit 1
fi

python3 - "$PUBLISH_WORKFLOW" "$WEEKLY_WORKFLOW" "$PROMOTE_WORKFLOW" <<'PY'
import pathlib
import sys
import yaml

publish_path = pathlib.Path(sys.argv[1])
weekly_path = pathlib.Path(sys.argv[2])
promote_path = pathlib.Path(sys.argv[3])
publish = yaml.safe_load(publish_path.read_text())
weekly = yaml.safe_load(weekly_path.read_text())
jobs = publish["jobs"]

assert set(jobs["release-allowlist"]["needs"]) == {"gate", "proxy", "languages"}
assert set(jobs["socket-proxy"]["needs"]) == {"gate", "release-allowlist"}

for job_name in ("languages", "proxy", "orchestrator", "socket-proxy"):
    builds = [step for step in jobs[job_name]["steps"] if "docker/build-push-action@" in step.get("uses", "")]
    assert len(builds) == 1
    assert builds[0].get("id") == "build"

for job_name in ("base", "languages", "proxy", "orchestrator", "socket-proxy"):
    builds = [step for step in jobs[job_name]["steps"] if "docker/build-push-action@" in step.get("uses", "")]
    assert len(builds) == 1
    assert builds[0]["with"]["push"] is True
    assert builds[0]["with"]["no-cache"] is True

orchestrator_build = next(
    step
    for step in jobs["orchestrator"]["steps"]
    if "docker/build-push-action@" in step.get("uses", "")
)
orchestrator_args = orchestrator_build["with"]["build-args"]
assert "RUNSECURE_VERSION=${{ needs.gate.outputs.version }}" in orchestrator_args
assert "RUNSECURE_BUILD_SHA=${{ github.sha }}" in orchestrator_args

release_steps = "\n".join(str(step) for step in jobs["release-allowlist"]["steps"])
socket_steps = "\n".join(str(step) for step in jobs["socket-proxy"]["steps"])
assert "generate-release-allowlist.sh" in release_steps
for artifact in (
    "release-digest-proxy",
    "release-digest-node-24",
    "release-digest-node-22",
    "release-digest-python-3.12",
    "release-digest-rust-stable",
):
    assert artifact in release_steps
assert "release-allowlist-" in socket_steps
manifest_steps = "\n".join(str(step) for step in jobs["release-manifest"]["steps"])
assert set(jobs["release-manifest"]["needs"]) == {"gate", "orchestrator", "socket-proxy"}
assert "generate-release-manifest.py" in manifest_steps
assert "release-image-manifest-" in manifest_steps

assert "Refresh socket-proxy allowed-images.txt" not in weekly_path.read_text()
for step in weekly["jobs"]["bump"]["steps"]:
    command = step.get("run", "")
    if "gh pr create" in command:
        assert "|| true" not in command

promote_text = promote_path.read_text()
assert "workflow_run:" not in promote_text
assert "workflow_dispatch:" in promote_text
PY

echo "PASS: release allowlist is digest-derived, complete, and built before socket-proxy"
