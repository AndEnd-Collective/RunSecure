#!/bin/bash
# ============================================================================
# RunSecure — GitHub Actions Workflow YAML Validity
# ============================================================================
# Asserts every file in .github/workflows/ is parseable YAML. GitHub's
# workflow validator is strict and rejects subtle errors (multi-line
# strings inside `run: |` literal blocks with column-0 continuations,
# expressions that reference unavailable contexts) — those errors only
# surface as "0 second failed runs" with no logs, which is hard to debug.
# Catch them locally instead.
#
# Requires: python3 + PyYAML on the host.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOWS_DIR="${RUNSECURE_ROOT}/.github/workflows"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not available (required for PyYAML validation)"
    exit 0
fi
if ! python3 -c 'import yaml' 2>/dev/null; then
    echo "SKIP: PyYAML not installed (pip install pyyaml)"
    exit 0
fi

shopt -s nullglob
for wf in "${WORKFLOWS_DIR}"/*.yml "${WORKFLOWS_DIR}"/*.yaml; do
    name=$(basename "$wf")
    err=$(python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$wf" 2>&1)
    if [ -z "$err" ]; then
        pass "$name parses as YAML"
    else
        # Truncate the noisy traceback to one informative line.
        msg=$(echo "$err" | grep -E 'yaml\.|Error' | tail -1)
        fail "$name: ${msg:-$err}"
    fi
done
shopt -u nullglob

# --- Workflow-specific shape checks (catch GH-Actions-only gotchas) ---------
# Job-level env: blocks must NOT reference workflow-level env contexts via
# ${{ env.X }} — those resolve empty at job-evaluation time. Step-level env
# is fine.
for wf in "${WORKFLOWS_DIR}"/*.yml; do
    name=$(basename "$wf")
    if python3 - "$wf" <<'PY' 2>/dev/null; then
import sys, yaml
data = yaml.safe_load(open(sys.argv[1]))
jobs = (data or {}).get("jobs", {}) or {}
problems = []
for jname, job in jobs.items():
    env = job.get("env") or {}
    for k, v in env.items():
        if isinstance(v, str) and "${{ env." in v:
            problems.append(f"{jname}.env.{k}")
if problems:
    print("\n".join(problems))
    sys.exit(2)
PY
        pass "$name: no job-level env references workflow-level env (GH gotcha avoided)"
    else
        fail "$name: job-level env references workflow-level env (will resolve empty — move to step-level env)"
    fi
done

# --- Print results -----------------------------------------------------------
echo ""
echo "=== Workflow YAML Validity ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
