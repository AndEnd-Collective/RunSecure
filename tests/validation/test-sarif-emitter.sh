#!/bin/bash
# End-to-end regression test for acceptance logs captured from Docker Compose.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

RAW_OUTPUT="${TMP_ROOT}/raw-output.log"
SARIF_OUTPUT="${TMP_ROOT}/acceptance.sarif"
STDERR_OUTPUT="${TMP_ROOT}/stderr.log"

{
    printf 'rs-acceptance-runner  | PASS: H01 runner uid is non-root\n'
    printf '\033[32mrs-acceptance-runner  |\033[0m FAIL: H03 apt still present\n'
    printf 'PASS: R01 CapEff is empty (cap_drop ALL)\n'
    printf 'rs-acceptance-runner  | SKIP: N01 dns probe — proxy unavailable\n'
    # run-all.sh replays failures in its end-of-run summary. That copy must
    # not inflate the number of executed checks or SARIF findings.
    printf 'rs-acceptance-runner  | FAIL: H03 apt still present\n'
    printf 'rs-acceptance-runner  | acceptance summary follows\n'
} > "$RAW_OUTPUT"

python3 "${RUNSECURE_ROOT}/tests/acceptance/sarif-emitter.py" \
    --claims "${RUNSECURE_ROOT}/tests/acceptance/claims.yml" \
    --image-ref "ghcr.io/example/node@sha256:test" \
    --commit-sha "deadbeef" \
    --output "$SARIF_OUTPUT" \
    < "$RAW_OUTPUT" 2> "$STDERR_OUTPUT"

python3 - "$SARIF_OUTPUT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    run = json.load(stream)["runs"][0]

expected = {"total-checks": 4, "passes": 2, "failures": 1, "skips": 1}
actual = {key: run["properties"][key] for key in expected}
if actual != expected:
    raise SystemExit(f"unexpected SARIF counters: {actual!r}")
if [result["ruleId"] for result in run["results"]] != ["H03"]:
    raise SystemExit(f"unexpected SARIF results: {run['results']!r}")
PY

grep -Fq 'sarif-emitter: 1 failures of 4 checks' "$STDERR_OUTPUT"
echo "PASS: Compose-prefixed acceptance results produce truthful SARIF counters and findings"
