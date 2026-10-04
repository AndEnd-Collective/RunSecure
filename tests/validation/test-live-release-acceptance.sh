#!/bin/bash
# Static contract for the operator-owned live release acceptance workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/live-release-acceptance.yml"
README="$ROOT/README.md"
SECURITY="$ROOT/SECURITY.md"

python3 - "$WORKFLOW" "$README" "$SECURITY" <<'PY'
from __future__ import annotations

import pathlib
import sys

import yaml

path = pathlib.Path(sys.argv[1])
workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
readme = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
security = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
jobs = workflow["jobs"]
runtime = jobs["runtime"]
verify = jobs["verify"]

trigger = workflow.get("on", workflow.get(True))
inputs = trigger["workflow_dispatch"]["inputs"]
assert inputs["expected_runner_image_ref"]["required"] is True
assert inputs["expected_proxy_image_ref"]["required"] is True
assert inputs["expected_scope"]["required"] is True

assert workflow["permissions"] == {}
assert workflow["concurrency"] == {
    "group": "live-release-acceptance",
    "cancel-in-progress": False,
}
assert runtime["runs-on"] == [
    "self-hosted",
    "Linux",
    "ARM64",
    "container",
    "runsecure-scope-${{ inputs.expected_scope }}",
]
assert runtime["permissions"] == {}
assert runtime["strategy"]["fail-fast"] is False
assert runtime["strategy"]["max-parallel"] == 4
assert runtime["strategy"]["matrix"]["slot"] == [1, 2, 3, 4]
assert len(runtime["steps"]) == 1
assert "uses" not in runtime["steps"][0]

runtime_script = runtime["steps"][0]["run"]
for required in (
    "RUNSECURE_VERSION",
    "RUNSECURE_BUILD_SHA",
    "RUNSECURE_RUNNER_IMAGE_REF",
    "RUNSECURE_PROXY_IMAGE_REF",
    "RUNSECURE_SCOPE",
    "RUNSECURE_SPAWN_ID",
    "HTTP_PROXY",
    "http_proxy",
    '[[ "${HTTPS_PROXY:-}" == "http://proxy:3128" ]]',
    '[[ "${NO_PROXY:-}" == "localhost,127.0.0.1" ]]',
    "-u ALL_PROXY -u all_proxy",
    'curl --disable --noproxy "*"',
    "runner reached GitHub directly",
    "RUNNER_TEMP",
    "sleep 30",
    "RUNSECURE_LIVE_COMPLETE scope=${RUNSECURE_SCOPE} slot=",
    "spawn=${RUNSECURE_SPAWN_ID}",
):
    assert required in runtime_script, required

assert verify["needs"] == "runtime"
assert verify["runs-on"] == "ubuntu-latest"
assert verify["permissions"] == {"actions": "read"}
assert len(verify["steps"]) == 2
verify_script = verify["steps"][0]["run"]
# `gh api repos/.../actions/jobs/<id>/logs` answers with a 302 to blob storage
# and `gh api` does not follow it, so stdout is empty and the completion marker
# can never be found — the gate was unpassable for every release until this was
# changed. Verified: `gh api -X GET .../logs` returned 0 bytes for a job whose
# log definitely contained the marker, while `gh run view --job <id> --log -R`
# returned 15471 bytes with it present. Following the redirect manually is not a
# fix either: the Authorization header rides along to Azure, which answers 401.
# Two approaches are known-broken and must not come back:
#   `gh api -X GET .../jobs/<id>/logs` — the endpoint 302s to blob storage and
#   gh api does not surface the body, so stdout is always empty (measured:
#   0 bytes for a job whose log definitely contained the marker).
#   `gh run view --job <id> --log` — requires the WHOLE run to be finished, but
#   verify runs inside that same run, so it is always empty there. This one
#   passes a local test against a completed run and still fails in CI, which is
#   exactly how it slipped through once.
# `gh api` is still fine for the job LIST; it is log fetching that must not go
# through gh. Requiring fetch_job_log/_NoRedirect above already forces the
# urllib path, so here just ban the gh run view form outright.
# Match the argv form only — the prose comment above the fetch deliberately
# names both broken approaches, and must not trip this.
assert '"--log"' not in verify_script, (
    "verify must not use gh run view --log; it cannot read logs mid-run"
)
assert "--config" in verify_script and "location" in verify_script, (
    "verify must fetch per-job logs with curl --config so the 302 is followed "
    "without resending the Authorization header and the token stays out of argv"
)
assert "Bearer {token}" in verify_script and "-H" not in verify_script, (
    "the token must be passed via curl --config on stdin, never as an argv -H"
)

for required in (
    "expected_parallelism must be between 1 and 4",
    "runtime job is missing a lifecycle timestamp",
    "has invalid timestamps",
    "expected 4 runtime jobs",
    "four distinct JIT runners",
    "maximum parallelism",
    # Logs must be fetched per-job via the REST endpoint, following the 302 to
    # blob storage WITHOUT resending the Authorization header.
    "def fetch_job_log(",
    '["curl", "--config", "-", api_url]',
    "/actions/jobs/{job_id}/logs",
    "len(body) > 0",
    "RUNSECURE_LIVE_COMPLETE scope={expected_scope}",
    "never contained their exact runtime completion",
    '"schema_version": 1',
    '"expected_version": expected_version',
    '"expected_build_sha": expected_build_sha',
    '"expected_runner_image_ref": expected_runner_image_ref',
    '"expected_proxy_image_ref": expected_proxy_image_ref',
    '"expected_scope": expected_scope',
    '"observed_max_parallelism": maximum',
    '"run_attempt": run_attempt',
):
    assert required in verify_script, required
assert '"--silent"' not in verify_script

upload = verify["steps"][1]
assert upload["uses"].startswith("actions/upload-artifact@")
assert upload["with"]["name"] == (
    "live-release-acceptance-${{ github.run_id }}-${{ github.run_attempt }}"
)
assert upload["with"]["path"] == ".live-acceptance/receipt.json"
assert upload["with"]["if-no-files-found"] == "error"

disproven_claim = "synchronous log upload wait still ensures"
assert disproven_claim not in readme.lower().replace("-", " ")
assert disproven_claim not in security.lower().replace("-", " ")
assert "*.blob.core.windows.net" in readme
assert "attacker-owned Azure account" in security

print("PASS: live release acceptance contract is complete and dependency-free")
PY

# Exercise the exact embedded verifier with a deterministic four-job fixture.
# The fourth job starts at the first job's completion timestamp; completion is
# processed first, proving the half-open concurrency calculation reports 3.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-live-acceptance-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

python3 - "$WORKFLOW" "$tmp/verifier.py" "$tmp/jobs.json" "$tmp/logs" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

import yaml

workflow_path = pathlib.Path(sys.argv[1])
verifier_path = pathlib.Path(sys.argv[2])
jobs_path = pathlib.Path(sys.argv[3])
logs_dir = pathlib.Path(sys.argv[4])
workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
script = workflow["jobs"]["verify"]["steps"][0]["run"]
start = "python3 - <<'PY'\n"
code = script.split(start, 1)[1].rsplit("\nPY", 1)[0]
verifier_path.write_text(code + "\n", encoding="utf-8")

jobs = []
intervals = (
    ("2026-07-21T00:00:00Z", "2026-07-21T00:00:30Z"),
    ("2026-07-21T00:00:01Z", "2026-07-21T00:00:31Z"),
    ("2026-07-21T00:00:02Z", "2026-07-21T00:00:32Z"),
    ("2026-07-21T00:00:30Z", "2026-07-21T00:01:00Z"),
)
logs_dir.mkdir()
for slot, (started, completed) in enumerate(intervals, start=1):
    job_id = 100 + slot
    spawn_id = f"spawn-{slot}"
    jobs.append(
        {
            "completed_at": completed,
            "conclusion": "success",
            "id": job_id,
            "name": f"runtime-{slot}",
            "runner_id": 200 + slot,
            "runner_name": f"rs-{spawn_id}-runner",
            "started_at": started,
        }
    )
    (logs_dir / f"{job_id}.log").write_text(
        "workflow source: spawn=${RUNSECURE_SPAWN_ID}\n"
        f"RUNSECURE_LIVE_COMPLETE scope=release-v2-1-9 "
        f"slot={slot} spawn={spawn_id}\n",
        encoding="utf-8",
    )
jobs_path.write_text(json.dumps({"jobs": jobs}), encoding="utf-8")
PY

mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'SH'
#!/bin/bash
set -euo pipefail
endpoint="${!#}"
case "$endpoint" in
  */runs/*/jobs\?*) cat "$GH_STUB_JOBS" ;;
  *) echo "unexpected gh endpoint: $endpoint" >&2; exit 2 ;;
esac
SH
chmod +x "$tmp/bin/gh"

# curl stub: drains the --config payload from stdin (so the real token never
# matters here) and serves the job log named by the API URL.
cat > "$tmp/bin/curl" <<'SH'
#!/bin/bash
set -euo pipefail
cat >/dev/null
url="${!#}"
job_id=${url%/logs}
job_id=${job_id##*/}
log="$GH_STUB_LOG_DIR/${job_id}.log"
[[ -f "$log" ]] || { echo "curl stub: no log for $job_id" >&2; exit 22; }
cat "$log"
SH
chmod +x "$tmp/bin/curl"

receipt="$tmp/receipt.json"
env \
  EXPECTED_BUILD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EXPECTED_PARALLELISM=3 \
  EXPECTED_PROXY_IMAGE_REF=ghcr.io/andend-collective/runsecure/proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  EXPECTED_RUNNER_IMAGE_REF=ghcr.io/andend-collective/runsecure/node@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  EXPECTED_SCOPE=release-v2-1-9 \
  EXPECTED_VERSION=2.1.9 \
  GH_TOKEN=stub-token-not-used \
  GH_STUB_JOBS="$tmp/jobs.json" \
  GH_STUB_LOG_DIR="$tmp/logs" \
  PATH="$tmp/bin:$PATH" \
  RECEIPT_PATH="$receipt" \
  REPOSITORY=AndEnd-Collective/RunSecure \
  RUN_ATTEMPT=2 \
  RUN_ID=12345 \
  python3 "$tmp/verifier.py"

python3 - "$receipt" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["schema_version"] == 1
assert receipt["run_id"] == 12345
assert receipt["run_attempt"] == 2
assert receipt["expected_version"] == "2.1.9"
assert receipt["expected_proxy_image_ref"].endswith("@sha256:" + "b" * 64)
assert receipt["expected_runner_image_ref"].endswith("@sha256:" + "c" * 64)
assert receipt["expected_scope"] == "release-v2-1-9"
assert receipt["observed_max_parallelism"] == 3
assert receipt["runtime_job_count"] == 4
assert len({job["runner_id"] for job in receipt["jobs"]}) == 4
assert all(job["log"]["verified"] for job in receipt["jobs"])
assert all(job["log"]["bytes"] > 0 for job in receipt["jobs"])
PY

invalid_output="$tmp/invalid-parallelism.txt"
if env \
  EXPECTED_BUILD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EXPECTED_PARALLELISM=0 \
  EXPECTED_PROXY_IMAGE_REF=ghcr.io/andend-collective/runsecure/proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  EXPECTED_RUNNER_IMAGE_REF=ghcr.io/andend-collective/runsecure/node@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  EXPECTED_SCOPE=release-v2-1-9 \
  EXPECTED_VERSION=2.1.9 \
  PATH="$tmp/bin:$PATH" \
  RECEIPT_PATH="$tmp/invalid.json" \
  REPOSITORY=AndEnd-Collective/RunSecure \
  RUN_ATTEMPT=1 \
  RUN_ID=12345 \
  python3 "$tmp/verifier.py" > "$invalid_output" 2>&1; then
  echo "FAIL: embedded verifier accepted parallelism zero" >&2
  exit 1
fi
grep -Fq 'expected_parallelism must be between 1 and 4' "$invalid_output"

echo "PASS: embedded live-acceptance verifier emits bound four-runner evidence"
