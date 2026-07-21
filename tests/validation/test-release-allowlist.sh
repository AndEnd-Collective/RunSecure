#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GENERATOR="${RUNSECURE_ROOT}/infra/socket-proxy/generate-release-allowlist.sh"
MANIFEST_GENERATOR="${RUNSECURE_ROOT}/infra/scripts/generate-release-manifest.py"
MANIFEST_VERIFIER="${RUNSECURE_ROOT}/infra/scripts/verify-release-manifest.py"
PUBLISH_WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/publish-images.yml"
ACCEPT_WORKFLOW="${RUNSECURE_ROOT}/.github/workflows/post-publish-acceptance.yml"
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
cat > "${tmp}/release-digest-base.txt" <<EOF
ghcr.io/andend-collective/runsecure/base@sha256:$(digest 9)
EOF
cat > "${tmp}/release-digest-node-24.txt" <<EOF
ghcr.io/andend-collective/runsecure/node@sha256:$(digest b)
EOF
cat > "${tmp}/release-digest-node-build-24.txt" <<EOF
ghcr.io/andend-collective/runsecure/node-build@sha256:$(digest 2)
EOF
cat > "${tmp}/release-digest-node-22.txt" <<EOF
ghcr.io/andend-collective/runsecure/node@sha256:$(digest c)
EOF
cat > "${tmp}/release-digest-node-build-22.txt" <<EOF
ghcr.io/andend-collective/runsecure/node-build@sha256:$(digest 3)
EOF
cat > "${tmp}/release-digest-python-3.12.txt" <<EOF
ghcr.io/andend-collective/runsecure/python@sha256:$(digest d)
EOF
cat > "${tmp}/release-digest-python-build-3.12.txt" <<EOF
ghcr.io/andend-collective/runsecure/python-build@sha256:$(digest 4)
EOF
cat > "${tmp}/release-digest-rust-stable.txt" <<EOF
ghcr.io/andend-collective/runsecure/rust@sha256:$(digest e)
EOF
cat > "${tmp}/release-digest-rust-build-stable.txt" <<EOF
ghcr.io/andend-collective/runsecure/rust-build@sha256:$(digest 5)
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
  --publish-run-id 123456 \
  --output "${tmp}/release-images.json" \
  "${tmp}"/release-digest-*.txt

python3 - "${tmp}/release-images.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema_version"] == 2
assert manifest["release"] == "2.1.8"
assert manifest["publish_run_id"] == 123456
assert set(manifest["images"]) == {
    "base",
    "node-build-22",
    "node-build-24",
    "node-22",
    "node-24",
    "orchestrator",
    "proxy",
    "python-build-3.12",
    "python-3.12",
    "rust-build-stable",
    "rust-stable",
    "socket-proxy",
}
assert "runsecure/orchestrator@sha256:" in manifest["images"]["orchestrator"]
assert "runsecure/socket-proxy@sha256:" in manifest["images"]["socket-proxy"]
PY

python3 "$MANIFEST_VERIFIER" "${tmp}/release-images.json" \
  --expected-release 2.1.8 \
  --expected-build-sha "$(digest 1 | cut -c1-40)" \
  --expected-publish-run-id 123456

if python3 "$MANIFEST_VERIFIER" "${tmp}/release-images.json" \
    --expected-publish-run-id 654321 2>/dev/null; then
  echo "FAIL: verifier accepted a manifest from another Publish Images run" >&2
  exit 1
fi

if python3 "$MANIFEST_GENERATOR" \
    --release 2.1.8 \
    --build-sha "$(digest 1 | cut -c1-40)" \
    --publish-run-id 123456 \
    --output "${tmp}/must-not-exist.json" \
    "${tmp}/release-digest-base.txt" \
    "${tmp}/release-digest-node-build-22.txt" \
    "${tmp}/release-digest-node-build-24.txt" \
    "${tmp}/release-digest-node-22.txt" \
    "${tmp}/release-digest-node-24.txt" \
    "${tmp}"/release-digest-orchestrator.txt \
    "${tmp}"/release-digest-proxy.txt \
    "${tmp}/release-digest-python-build-3.12.txt" \
    "${tmp}"/release-digest-python-3.12.txt \
    "${tmp}/release-digest-rust-build-stable.txt" \
    "${tmp}"/release-digest-rust-stable.txt 2>/dev/null; then
  echo "FAIL: release manifest accepted a missing socket-proxy digest" >&2
  exit 1
fi

if python3 "$MANIFEST_GENERATOR" \
    --release 2.1.8 \
    --build-sha "$(digest 1 | cut -c1-40)" \
    --publish-run-id 123456 \
    --output "${tmp}/must-not-exist.json" \
    "${tmp}/release-digest-node-build-22.txt" \
    "${tmp}/release-digest-node-build-24.txt" \
    "${tmp}/release-digest-node-22.txt" \
    "${tmp}/release-digest-node-24.txt" \
    "${tmp}"/release-digest-orchestrator.txt \
    "${tmp}"/release-digest-proxy.txt \
    "${tmp}/release-digest-python-build-3.12.txt" \
    "${tmp}"/release-digest-python-3.12.txt \
    "${tmp}/release-digest-rust-build-stable.txt" \
    "${tmp}"/release-digest-rust-stable.txt \
    "${tmp}"/release-digest-socket-proxy.txt 2>/dev/null; then
  echo "FAIL: release manifest accepted a missing base digest" >&2
  exit 1
fi

python3 - "$PUBLISH_WORKFLOW" "$WEEKLY_WORKFLOW" "$PROMOTE_WORKFLOW" "$ACCEPT_WORKFLOW" <<'PY'
import pathlib
import sys
import yaml

publish_path = pathlib.Path(sys.argv[1])
weekly_path = pathlib.Path(sys.argv[2])
promote_path = pathlib.Path(sys.argv[3])
accept_path = pathlib.Path(sys.argv[4])
publish = yaml.safe_load(publish_path.read_text())
weekly = yaml.safe_load(weekly_path.read_text())
jobs = publish["jobs"]

assert publish["concurrency"] == {
    "group": "publish-images",
    "cancel-in-progress": False,
}
assert jobs["base"]["outputs"]["digest"] == "${{ steps.build.outputs.digest }}"
assert set(jobs["release-allowlist"]["needs"]) == {"gate", "proxy", "languages"}
assert set(jobs["socket-proxy"]["needs"]) == {"gate", "release-allowlist"}

for job_name in ("base", "proxy", "orchestrator", "socket-proxy"):
    builds = [step for step in jobs[job_name]["steps"] if "docker/build-push-action@" in step.get("uses", "")]
    assert len(builds) == 1
    assert builds[0].get("id") == "build"

language_builds = [
    step
    for step in jobs["languages"]["steps"]
    if "docker/build-push-action@" in step.get("uses", "")
]
assert {step.get("id") for step in language_builds} == {"build-stage", "build"}
builder = next(step for step in language_builds if step["id"] == "build-stage")
terminal = next(step for step in language_builds if step["id"] == "build")
assert builder["with"]["target"] == "${{ matrix.name }}-build"
assert "${{ matrix.name }}-build" in builder["with"]["tags"]
assert "BASE_REF=${{ env.IMAGE_PREFIX }}/base@${{ needs.base.outputs.digest }}" in builder["with"]["build-args"]
assert "BASE_TAG=" not in builder["with"]["build-args"]
assert terminal["with"]["file"] == "images/finalize-language.Dockerfile"
assert "BUILD_DIGEST=${{ steps.build-stage.outputs.digest }}" in terminal["with"]["build-args"]
assert "COMPOSITION_BASE=" in terminal["with"]["build-args"]

for job_name in ("base", "proxy", "orchestrator", "socket-proxy"):
    builds = [step for step in jobs[job_name]["steps"] if "docker/build-push-action@" in step.get("uses", "")]
    assert len(builds) == 1
    assert builds[0]["with"]["push"] is True
    assert builds[0]["with"]["no-cache"] is True
for build in language_builds:
    assert build["with"]["push"] is True
    assert build["with"]["no-cache"] is True

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
for build_only_artifact in (
    "release-digest-node-build-24",
    "release-digest-node-build-22",
    "release-digest-python-build-3.12",
    "release-digest-rust-build-stable",
):
    assert build_only_artifact not in release_steps
assert "release-allowlist-" in socket_steps
manifest_steps = "\n".join(str(step) for step in jobs["release-manifest"]["steps"])
assert set(jobs["release-manifest"]["needs"]) == {
    "gate",
    "base",
    "orchestrator",
    "socket-proxy",
}
assert "generate-release-manifest.py" in manifest_steps
assert "--publish-run-id '${{ github.run_id }}'" in manifest_steps
assert "release-image-manifest-" in manifest_steps
assert set(jobs["grype-scan-languages"]["needs"]) == {"gate", "languages"}
language_scans = jobs["grype-scan-languages"]["strategy"]["matrix"]["include"]
assert len(language_scans) == 8
assert {row["platform"] for row in language_scans} == {"linux/amd64", "linux/arm64"}
assert {row["platform_slug"] for row in language_scans} == {"amd64", "arm64"}
assert {
    (row["name"], str(row["lang_version"]), row["platform"])
    for row in language_scans
} == {
    ("node", "24", "linux/amd64"),
    ("node", "24", "linux/arm64"),
    ("node", "22", "linux/amd64"),
    ("node", "22", "linux/arm64"),
    ("python", "3.12", "linux/amd64"),
    ("python", "3.12", "linux/arm64"),
    ("rust", "stable", "linux/amd64"),
    ("rust", "stable", "linux/arm64"),
}
rust_scans = [row for row in language_scans if row["name"] == "rust"]
assert len(rust_scans) == 2
assert all(
    row["expected_presence_cataloger"] == "binary-classifier-cataloger"
    and row["expected_presence_package"] == "rust"
    for row in rust_scans
)

assert "Refresh socket-proxy allowed-images.txt" not in weekly_path.read_text()
weekly_text = weekly_path.read_text()
assert "secrets.RELEASE_TOKEN || secrets.GITHUB_TOKEN" not in weekly_text
assert "token: ${{ secrets.RELEASE_TOKEN }}" in weekly_text
assert weekly_text.index("Require the release cascade token") < weekly_text.index("Create and push tag")
dependency_pr_steps = [
    step
    for step in weekly["jobs"]["bump"]["steps"]
    if "gh pr create" in step.get("run", "")
]
assert len(dependency_pr_steps) == 1
dependency_pr_step = dependency_pr_steps[0]
dependency_pr_command = dependency_pr_step["run"]
assert "continue-on-error" not in dependency_pr_step
assert "|| true" not in dependency_pr_command
assert "if PR_OUTPUT=$(gh pr create" in dependency_pr_command
assert "GitHub Actions is not permitted to create or approve pull requests" in dependency_pr_command
assert "::warning title=Go dependency PR requires operator action::" in dependency_pr_command
assert 'pull/new/${BRANCH}' in dependency_pr_command
assert 'exit "$PR_STATUS"' in dependency_pr_command
assert "The release tag and image cascade remain valid" in dependency_pr_command

promote_text = promote_path.read_text()
promote = yaml.safe_load(promote_text)
assert "workflow_run:" not in promote_text
assert "workflow_dispatch:" in promote_text
assert promote["concurrency"] == {
    "group": "promote-stable",
    "cancel-in-progress": False,
}
assert "--clobber" not in promote_text
assert "publish_run_id:" in promote_text
assert "acceptance_run_id:" in promote_text
assert "live_acceptance_run_id:" in promote_text
assert "run-id: ${{ inputs.publish_run_id }}" in promote_text
assert "run-id: ${{ inputs.acceptance_run_id }}" in promote_text
assert "run-id: ${{ inputs.live_acceptance_run_id }}" in promote_text
assert "verified-publish-manifest-${{ inputs.publish_run_id }}" in promote_text
assert "live-release-acceptance-${LIVE_ACCEPTANCE_RUN_ID}-${RUN_ATTEMPT}" in promote_text
assert "verify-release-manifest.py" in promote_text
assert "cmp -s .publish-manifest/release-images.json" in promote_text
assert 'run.get("event") != "workflow_run"' in promote_text
assert 'run.get("head_branch") != f"v{expected_version}"' in promote_text
assert 'run.get("name") != "live-release-acceptance"' in promote_text
assert 'run.get("event") != "workflow_dispatch"' in promote_text
assert 'run.get("head_sha") != build_sha' in promote_text
assert 'receipt.get("expected_version") != expected_version' in promote_text
assert 'receipt.get("expected_build_sha") != build_sha' in promote_text
assert 'receipt.get("all_logs_verified") is not True' in promote_text
assert 'expected_parallelism != 3 or observed_parallelism != 3' in promote_text
assert 'log.get("completion_marker") != expected_marker' in promote_text
assert "promote-release-images.py" in promote_text
assert promote_text.count("verify-remote-release-tag.sh") >= 4
assert "strategy" not in promote["jobs"]["promote"]
release_checkout = promote["jobs"]["release"]["steps"][0]
assert release_checkout["with"]["ref"] == "${{ needs.resolve-manifest.outputs.build_sha }}"
assert "--verify-tag" in promote_text
assert "gh release upload" in promote_text
assert "runsecure-v${VERSION}-release-images.json" in promote_text

accept_text = accept_path.read_text()
assert "github.event.workflow_run.id || inputs.publish_run_id" in accept_text
assert "git tag -l" not in accept_text
assert "verify-release-manifest.py" in accept_text
assert "PROXY_IMAGE_REF=" in accept_text
assert "RUNNER_IMAGE_REF=" in accept_text
assert '[[ ! "$RUNNER_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]' in accept_text
assert "--entrypoint node" in accept_text
assert "--entrypoint python3" in accept_text
assert "rustc --version" in accept_text
assert "cargo --version" in accept_text
assert 'rustc "$work/main.rs"' in accept_text
PY

# Execute the exact embedded live-receipt validator with a valid fixture, then
# prove that release-SHA drift and source-only (unrendered) log markers fail.
python3 - \
  "$PROMOTE_WORKFLOW" \
  "${tmp}/verify-live-receipt.py" \
  "${tmp}/live-run.json" \
  "${tmp}/live-receipt.json" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

import yaml

workflow_path = pathlib.Path(sys.argv[1])
validator_path = pathlib.Path(sys.argv[2])
run_path = pathlib.Path(sys.argv[3])
receipt_path = pathlib.Path(sys.argv[4])
workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
script = next(
    step["run"]
    for step in workflow["jobs"]["resolve-manifest"]["steps"]
    if step.get("id") == "verify"
)
start = '  "$REPOSITORY" <<\'PY\'\n'
validator = script.split(start, 1)[1].split("\nPY\n", 1)[0]
validator_path.write_text(validator + "\n", encoding="utf-8")

build_sha = "a" * 40
run = {
    "conclusion": "success",
    "event": "workflow_dispatch",
    "head_branch": "v2.1.9",
    "head_sha": build_sha,
    "id": 777,
    "name": "live-release-acceptance",
    "path": ".github/workflows/live-release-acceptance.yml",
    "repository": {"full_name": "AndEnd-Collective/RunSecure"},
    "run_attempt": 2,
}
jobs = []
for slot in range(1, 5):
    spawn_id = f"spawn-{slot}"
    jobs.append(
        {
            "completed_at": f"2026-07-21T00:00:{30 + slot:02d}Z",
            "conclusion": "success",
            "job_id": 100 + slot,
            "job_name": f"runtime-{slot}",
            "log": {
                "bytes": 1000 + slot,
                "completion_marker": (
                    f"RUNSECURE_LIVE_COMPLETE slot={slot} spawn={spawn_id}"
                ),
                "verified": True,
            },
            "runner_id": 200 + slot,
            "runner_name": f"rs-{spawn_id}-runner",
            "started_at": f"2026-07-21T00:00:0{slot}Z",
        }
    )
receipt = {
    "all_logs_verified": True,
    "all_runtime_jobs_successful": True,
    "expected_build_sha": build_sha,
    "expected_parallelism": 3,
    "expected_version": "2.1.9",
    "jobs": jobs,
    "observed_max_parallelism": 3,
    "repository": "AndEnd-Collective/RunSecure",
    "run_attempt": 2,
    "run_id": 777,
    "runtime_job_count": 4,
    "schema_version": 1,
    "workflow_path": ".github/workflows/live-release-acceptance.yml",
}
run_path.write_text(json.dumps(run), encoding="utf-8")
receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
PY

build_sha=$(printf 'a%.0s' {1..40})
python3 "${tmp}/verify-live-receipt.py" \
  "${tmp}/live-run.json" "${tmp}/live-receipt.json" \
  2.1.9 "$build_sha" 777 AndEnd-Collective/RunSecure

python3 - "${tmp}/live-run.json" "${tmp}/wrong-sha-run.json" <<'PY'
import json
import pathlib
import sys

run = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
run["head_sha"] = "b" * 40
pathlib.Path(sys.argv[2]).write_text(json.dumps(run), encoding="utf-8")
PY
if python3 "${tmp}/verify-live-receipt.py" \
    "${tmp}/wrong-sha-run.json" "${tmp}/live-receipt.json" \
    2.1.9 "$build_sha" 777 AndEnd-Collective/RunSecure 2>/dev/null; then
  echo "FAIL: promotion accepted live evidence from a different build SHA" >&2
  exit 1
fi

python3 - "${tmp}/live-receipt.json" "${tmp}/source-marker-receipt.json" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt["jobs"][0]["log"]["completion_marker"] = (
    "RUNSECURE_LIVE_COMPLETE slot=1 spawn=${RUNSECURE_SPAWN_ID}"
)
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt), encoding="utf-8")
PY
if python3 "${tmp}/verify-live-receipt.py" \
    "${tmp}/live-run.json" "${tmp}/source-marker-receipt.json" \
    2.1.9 "$build_sha" 777 AndEnd-Collective/RunSecure 2>/dev/null; then
  echo "FAIL: promotion accepted an unrendered workflow-source log marker" >&2
  exit 1
fi

python3 - "${tmp}/live-receipt.json" "${tmp}/serial-receipt.json" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt["expected_parallelism"] = 1
receipt["observed_max_parallelism"] = 1
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt), encoding="utf-8")
PY
if python3 "${tmp}/verify-live-receipt.py" \
    "${tmp}/live-run.json" "${tmp}/serial-receipt.json" \
    2.1.9 "$build_sha" 777 AndEnd-Collective/RunSecure 2>/dev/null; then
  echo "FAIL: promotion accepted a serial live-acceptance run" >&2
  exit 1
fi

# Execute the dependency-refresh step with stubbed Go/Git/GitHub commands so
# the policy-error exception is proven narrow rather than merely linted.
python3 - "$WEEKLY_WORKFLOW" "${tmp}/refresh-go-dependencies.sh" <<'PY'
import pathlib
import sys
import yaml

workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["bump"]["steps"]
command = next(step["run"] for step in steps if "gh pr create" in step.get("run", ""))
pathlib.Path(sys.argv[2]).write_text(command)
PY

mkdir -p "${tmp}/stub-bin"
cat > "${tmp}/stub-bin/go" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "${tmp}/stub-bin/git" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "diff" ]]; then
  exit 1
fi
exit 0
EOF
cat > "${tmp}/stub-bin/gh" <<'EOF'
#!/bin/bash
printf '%s\n' "${GH_STUB_OUTPUT:-https://github.example/pull/1}"
exit "${GH_STUB_STATUS:-0}"
EOF
chmod +x "${tmp}/stub-bin/go" "${tmp}/stub-bin/git" "${tmp}/stub-bin/gh"

summary="${tmp}/policy-summary.md"
policy_output="${tmp}/policy-output.txt"
policy_error='pull request create failed: GraphQL: GitHub Actions is not permitted to create or approve pull requests (createPullRequest)'
if ! env \
  PATH="${tmp}/stub-bin:${PATH}" \
  GH_STUB_STATUS=1 \
  GH_STUB_OUTPUT="$policy_error" \
  GITHUB_REPOSITORY=AndEnd-Collective/RunSecure \
  GITHUB_SERVER_URL=https://github.com \
  GITHUB_STEP_SUMMARY="$summary" \
  NEXT_VERSION=v9.9.9 \
  bash "${tmp}/refresh-go-dependencies.sh" > "$policy_output" 2>&1; then
  echo "FAIL: the known GitHub Actions PR-policy denial failed the release job" >&2
  exit 1
fi
if ! grep -Fq '::warning title=Go dependency PR requires operator action::' "$policy_output" || \
   ! grep -Fq 'https://github.com/AndEnd-Collective/RunSecure/pull/new/bot/go-deps-v9.9.9' "$summary"; then
  echo "FAIL: the known PR-policy denial did not produce actionable operator guidance" >&2
  exit 1
fi

unexpected_output="${tmp}/unexpected-output.txt"
set +e
env \
  PATH="${tmp}/stub-bin:${PATH}" \
  GH_STUB_STATUS=23 \
  GH_STUB_OUTPUT='unexpected GitHub API failure' \
  GITHUB_REPOSITORY=AndEnd-Collective/RunSecure \
  GITHUB_SERVER_URL=https://github.com \
  GITHUB_STEP_SUMMARY="${tmp}/unexpected-summary.md" \
  NEXT_VERSION=v9.9.9 \
  bash "${tmp}/refresh-go-dependencies.sh" > "$unexpected_output" 2>&1
unexpected_status=$?
set -e
if [[ "$unexpected_status" -ne 23 ]] || \
   ! grep -Fq '::error title=Go dependency PR creation failed::' "$unexpected_output"; then
  echo "FAIL: an unexpected PR-creation error was masked or reclassified" >&2
  exit 1
fi

echo "PASS: release allowlist is digest-derived, complete, and built before socket-proxy"
