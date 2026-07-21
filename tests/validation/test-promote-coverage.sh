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
    && grep -q 'verified-publish-manifest-${{ inputs.publish_run_id }}' "$PROMOTE_WF" \
    && grep -q 'run-id: ${{ inputs.acceptance_run_id }}' "$PROMOTE_WF"; then
    pass "promotion requires the exact post-publish acceptance artifact"
else
    fail "promotion does not bind acceptance to the exact publish manifest"
fi

if grep -qE '^[[:space:]]+workflow_run:' "$PROMOTE_WF"; then
    fail "promote-to-stable.yml: automatic workflow_run promotion is forbidden"
else
    pass "promote-to-stable.yml: stable promotion requires manual dispatch"
fi

if grep -qE '^[[:space:]]+workflow_dispatch:' "$PROMOTE_WF"; then
    pass "promote-to-stable.yml: manual dispatch trigger is present"
else
    fail "promote-to-stable.yml: manual dispatch trigger is missing"
fi

if grep -qE '^[[:space:]]+workflow_run:' "$ACCEPT_WF" \
    && grep -q 'workflows: \["Publish Images"\]' "$ACCEPT_WF"; then
    pass "post-publish acceptance remains automatic after image publication"
else
    fail "post-publish acceptance must run automatically after Publish Images"
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
