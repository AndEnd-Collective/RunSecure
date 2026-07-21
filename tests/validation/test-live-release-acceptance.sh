#!/bin/bash
# Static contract for the operator-owned live release acceptance workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/live-release-acceptance.yml"

python3 - "$WORKFLOW" <<'PY'
from __future__ import annotations

import pathlib
import sys

import yaml

path = pathlib.Path(sys.argv[1])
workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
jobs = workflow["jobs"]
runtime = jobs["runtime"]
verify = jobs["verify"]

assert workflow["permissions"] == {}
assert workflow["concurrency"] == {
    "group": "live-release-acceptance",
    "cancel-in-progress": False,
}
assert runtime["runs-on"] == ["self-hosted", "Linux", "ARM64", "container"]
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
    "RUNSECURE_SCOPE",
    "RUNSECURE_SPAWN_ID",
    "HTTP_PROXY",
    "http_proxy",
    "RUNNER_TEMP",
    "sleep 30",
    "RUNSECURE_LIVE_COMPLETE slot=",
    "spawn=${RUNSECURE_SPAWN_ID}",
):
    assert required in runtime_script, required

assert verify["needs"] == "runtime"
assert verify["runs-on"] == "ubuntu-latest"
assert verify["permissions"] == {"actions": "read"}
assert len(verify["steps"]) == 2
verify_script = verify["steps"][0]["run"]
for required in (
    "expected_parallelism must be between 1 and 4",
    "runtime job is missing a lifecycle timestamp",
    "has invalid timestamps",
    "expected 4 runtime jobs",
    "four distinct JIT runners",
    "maximum parallelism",
    "/actions/jobs/{job_id}/logs",
    "len(result.stdout) > 0",
    "RUNSECURE_LIVE_COMPLETE slot={slot} spawn={spawn_id}",
    "never contained their exact runtime completion",
    '"schema_version": 1',
    '"expected_version": expected_version',
    '"expected_build_sha": expected_build_sha',
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
        f"RUNSECURE_LIVE_COMPLETE slot={slot} spawn={spawn_id}\n",
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
  */jobs/*/logs)
    job_id=${endpoint%/logs}
    job_id=${job_id##*/}
    cat "$GH_STUB_LOG_DIR/${job_id}.log"
    ;;
  *) echo "unexpected gh endpoint: $endpoint" >&2; exit 2 ;;
esac
SH
chmod +x "$tmp/bin/gh"

receipt="$tmp/receipt.json"
env \
  EXPECTED_BUILD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EXPECTED_PARALLELISM=3 \
  EXPECTED_VERSION=2.1.9 \
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
