#!/bin/bash
# ============================================================================
# RunSecure — Promote-to-Stable Coverage Lint
# ============================================================================
# Asserts every published image kind has a release-promotion plan entry, so
# an image can't be built + Grype-scanned + pushed as `<ver>-canary` yet never
# promoted to the stable `<ver>` / `latest` tags.
#
# This guards the exact regression where the orchestrator + socket-proxy
# control-plane images were omitted from promote-to-stable's matrix (they were
# added to publish-images for the Compose-backed orchestrator, but the promote
# matrix was never updated), leaving operators with only `-canary` tags.
#
# Pure file-content check — no Docker required.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOWS_DIR="${RUNSECURE_ROOT}/.github/workflows"
PROMOTE_WF="${WORKFLOWS_DIR}/promote-to-stable.yml"
ACCEPT_WF="${WORKFLOWS_DIR}/post-publish-acceptance.yml"
PROMOTE_SCRIPT="${RUNSECURE_ROOT}/infra/scripts/promote-release-images.py"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

if [[ ! -f "$PROMOTE_WF" ]]; then
    echo "FAILED: promote-to-stable.yml not found at $PROMOTE_WF"
    exit 1
fi

if python3 - "$PROMOTE_SCRIPT" <<'PY'
import importlib.util
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("runsecure_promoter_coverage", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

assert len(module.PROMOTIONS) == 12
assert {item.package for item in module.PROMOTIONS} == {
    "base",
    "proxy",
    "orchestrator",
    "socket-proxy",
    "node",
    "node-build",
    "python",
    "python-build",
    "rust",
    "rust-build",
}
assert len({item.manifest_key for item in module.PROMOTIONS}) == 12
assert len({(item.package, item.stable_suffix) for item in module.PROMOTIONS}) == 12
PY
then
    pass "promotion plan covers all 12 published image variants exactly once"
else
    fail "promotion plan is incomplete or contains duplicate destinations"
fi

if grep -q 'promote-release-images.py' "$PROMOTE_WF"; then
    pass "promote-to-stable.yml invokes the aggregate release promotion plan"
else
    fail "promote-to-stable.yml bypasses the aggregate release promotion plan"
fi

if grep -q 'acceptance_run_id:' "$PROMOTE_WF" \
    && grep -q 'verified-publish-manifest-${{ needs.resolve-inputs.outputs.publish_run_id }}' "$PROMOTE_WF" \
    && grep -q 'run-id: ${{ needs.resolve-inputs.outputs.acceptance_run_id }}' "$PROMOTE_WF"; then
    pass "promotion requires the exact post-publish acceptance artifact"
else
    fail "promotion does not bind acceptance to the exact publish manifest"
fi

if grep -q 'live_acceptance_run_id:' "$PROMOTE_WF" \
    && grep -Fq 'live-release-acceptance-${LIVE_ACCEPTANCE_RUN_ID}-${RUN_ATTEMPT}' "$PROMOTE_WF" \
    && grep -Fq 'run-id: ${{ needs.resolve-inputs.outputs.live_acceptance_run_id }}' "$PROMOTE_WF" \
    && grep -Fq 'run.get("head_branch") != f"v{expected_version}"' "$PROMOTE_WF" \
    && grep -Fq 'run.get("head_sha") != build_sha' "$PROMOTE_WF" \
    && grep -Fq 'receipt.get("all_logs_verified") is not True' "$PROMOTE_WF" \
    && grep -Fq 'receipt.get("expected_runner_image_ref") != images.get("node-24")' "$PROMOTE_WF" \
    && grep -Fq 'receipt.get("expected_proxy_image_ref") != images.get("proxy")' "$PROMOTE_WF" \
    && grep -Fq 'receipt.get("expected_scope") != expected_scope' "$PROMOTE_WF" \
    && grep -Fq 'expected_parallelism != 3 or observed_parallelism != 3' "$PROMOTE_WF"; then
    pass "a supplied live receipt is verified against the exact tag, images, scope and job logs"
else
    fail "promotion no longer verifies a supplied live acceptance receipt"
fi

# The live receipt is optional, but never half-supplied: a run ID without its
# scope (or the reverse) must fail instead of silently skipping the check.
if grep -Fq 'if [ -n "$LIVE_ACCEPTANCE_RUN_ID" ] || [ -n "$EXPECTED_SCOPE" ]; then' "$PROMOTE_WF" \
    && grep -Fq 'expected_scope is required with live_acceptance_run_id' "$PROMOTE_WF" \
    && grep -Fq "if: needs.resolve-inputs.outputs.live_acceptance_run_id != ''" "$PROMOTE_WF"; then
    pass "live receipt is optional but all-or-nothing"
else
    fail "live receipt inputs can be half-supplied or are no longer optional"
fi

if grep -Fq 'run.get("head_branch") != f"v{expected_version}"' "$PROMOTE_WF"; then
    pass "promotion accepts only the expected version-tag Publish Images run"
else
    fail "promotion does not bind the accepted run to vEXPECTED_VERSION"
fi

if [[ $(grep -c 'verify-remote-release-tag.sh' "$PROMOTE_WF") -ge 4 ]] \
    && grep -Fq 'ref: ${{ needs.resolve-manifest.outputs.build_sha }}' "$PROMOTE_WF" \
    && grep -Fq -- '--verify-tag' "$PROMOTE_WF"; then
    pass "promotion and release re-fetch the tag, run at BUILD_SHA, and verify the tag"
else
    fail "promotion or release can mutate without a fresh exact tag/build check"
fi

# Promotion is unattended: it follows a successful post-publish-acceptance run
# with no human step, and nothing else may start it automatically.
if python3 - "$PROMOTE_WF" <<'PY'
import pathlib
import sys
import yaml

workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
triggers = workflow[True]
assert set(triggers) == {"workflow_run", "workflow_dispatch"}, set(triggers)
assert triggers["workflow_run"] == {"workflows": ["post-publish-acceptance"], "types": ["completed"]}
jobs = workflow["jobs"]
assert jobs["resolve-manifest"]["needs"] == "resolve-inputs"
assert jobs["resolve-manifest"]["if"] == "needs.resolve-inputs.outputs.proceed == 'true'"
assert jobs["promote"]["needs"] == "resolve-manifest"
for name, job in jobs.items():
    assert "environment" not in job, f"{name}: an environment gate would reintroduce a manual approval"
PY
then
    pass "promote-to-stable.yml: promotion follows post-publish acceptance with no manual gate"
else
    fail "promote-to-stable.yml: promotion is not wired to run unattended after acceptance"
fi

if grep -qE '^[[:space:]]+workflow_dispatch:' "$PROMOTE_WF"; then
    pass "promote-to-stable.yml: manual dispatch remains available for a re-run"
else
    fail "promote-to-stable.yml: manual dispatch trigger is missing"
fi

# Execute the trigger-resolution step with a stubbed gh. An automatic
# promotion may start only for a successful acceptance of a pushed release
# tag; every other completion of the acceptance workflow must stop cleanly.
resolve_tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-promote-resolve-XXXXXX")
python3 - "$PROMOTE_WF" "${resolve_tmp}/resolve.sh" <<'PY'
import pathlib
import sys
import yaml

workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
step = next(s for s in workflow["jobs"]["resolve-inputs"]["steps"] if s.get("id") == "resolve")
pathlib.Path(sys.argv[2]).write_text(step["run"])
PY
mkdir -p "${resolve_tmp}/bin"
cat > "${resolve_tmp}/bin/gh" <<'STUB'
#!/bin/bash
for argument in "$@"; do
  case "$argument" in
    */artifacts) printf '%s\n' $STUB_ARTIFACTS; exit 0 ;;
    */actions/runs/*) printf '%s\t%s\n' "$STUB_EVENT" "$STUB_REF"; exit 0 ;;
  esac
done
exit 1
STUB
chmod +x "${resolve_tmp}/bin/gh"

# resolve_case NAME EXPECTED_EXIT EXPECTED_OUTPUT_LINE [ENV=VALUE...]
resolve_case() {
    local name="$1" expected_exit="$2" expected_line="$3"
    shift 3
    local output="${resolve_tmp}/output" status=0
    : > "$output"
    env PATH="${resolve_tmp}/bin:${PATH}" GITHUB_OUTPUT="$output" REPOSITORY=owner/repo \
        TRIGGER_RUN_ID=500 "$@" bash "${resolve_tmp}/resolve.sh" >/dev/null 2>&1 || status=$?
    if [[ "$status" == "$expected_exit" ]] && { [[ -z "$expected_line" ]] || grep -qxF "$expected_line" "$output"; }; then
        pass "automatic promotion: ${name}"
    else
        fail "automatic promotion: ${name} (exit=${status}, output: $(tr '\n' ' ' < "$output"))"
    fi
}
resolve_case "accepted release tag resolves version and publish run" 0 "image_version=3.0.0" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="acceptance-logs verified-publish-manifest-400" STUB_EVENT=push STUB_REF=v3.0.0
resolve_case "accepted release tag binds the exact publish run" 0 "publish_run_id=400" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="acceptance-logs verified-publish-manifest-400" STUB_EVENT=push STUB_REF=v3.0.0
resolve_case "failed acceptance does not promote" 0 "proceed=false" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=failure
resolve_case "skipped acceptance does not promote" 0 "proceed=false" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=skipped
resolve_case "manual build does not promote" 0 "proceed=false" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="verified-publish-manifest-400" STUB_EVENT=workflow_dispatch STUB_REF=main
resolve_case "non-release tag does not promote" 0 "proceed=false" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="verified-publish-manifest-400" STUB_EVENT=push STUB_REF=v3.0.0-rc1
resolve_case "ambiguous publish manifest fails" 1 "" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="verified-publish-manifest-400 verified-publish-manifest-401" STUB_EVENT=push STUB_REF=v3.0.0
resolve_case "missing publish manifest fails" 1 "" \
    EVENT_NAME=workflow_run TRIGGER_CONCLUSION=success \
    STUB_ARTIFACTS="acceptance-logs" STUB_EVENT=push STUB_REF=v3.0.0
resolve_case "manual dispatch passes its inputs through" 0 "acceptance_run_id=2" \
    EVENT_NAME=workflow_dispatch INPUT_IMAGE_VERSION=3.0.0 INPUT_PUBLISH_RUN_ID=1 \
    INPUT_ACCEPTANCE_RUN_ID=2 INPUT_LIVE_ACCEPTANCE_RUN_ID= INPUT_EXPECTED_SCOPE=
rm -rf "$resolve_tmp"

if grep -qE '^[[:space:]]+workflow_run:' "$ACCEPT_WF" \
    && grep -q 'workflows: \["Publish Images"\]' "$ACCEPT_WF"; then
    pass "post-publish acceptance remains automatic after image publication"
else
    fail "post-publish acceptance must run automatically after Publish Images"
fi

if grep -Fq '[[ ! "$RUNNER_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]' "$ACCEPT_WF" \
    && grep -Fq -- '--entrypoint node' "$ACCEPT_WF" \
    && grep -Fq -- '--entrypoint python3' "$ACCEPT_WF" \
    && grep -Fq 'rustc "$work/main.rs"' "$ACCEPT_WF"; then
    pass "post-publish acceptance executes all language runtimes by exact digest"
else
    fail "post-publish acceptance does not execute every exact-digest runtime"
fi

echo ""
echo "=== Promote-to-Stable Coverage ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
