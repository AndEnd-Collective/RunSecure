#!/bin/bash
# ============================================================================
# RunSecure — JIT Entrypoint Baking + Scope-Hygiene Assertions (#54 follow-up)
# ============================================================================
# Static, Docker-free assertions guarding two generalized fixes:
#
#   G2/G3: images/base.Dockerfile bakes infra/scripts/entrypoint.sh into
#          every runner image (COPY) and sets it as the image ENTRYPOINT, so
#          orchestrator-spawned runner containers (created directly via the
#          Docker API, not through infra/docker-compose.yml's own entrypoint
#          override) actually launch the JIT agent instead of starting with
#          no process at all.
#
#   G8:    .gitignore ignores every operator-authored file under
#          infra/orchestrator/scopes/ EXCEPT the tracked example.yml
#          template, so hand-patched, project-specific scope artifacts
#          (env files, real scope YAMLs, ad-hoc runner Dockerfiles, extra
#          allowlist files) never leak into a commit.
#
# Usage:
#   bash tests/validation/test-runner-entrypoint-baked.sh
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BASE_DOCKERFILE="${RUNSECURE_ROOT}/images/base.Dockerfile"
GITIGNORE="${RUNSECURE_ROOT}/.gitignore"

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }

echo -e "\n${BOLD}=== JIT Entrypoint Baking + Scope-Hygiene Tests ===${NC}\n"

# ============================================================================
# G2/G3 — images/base.Dockerfile bakes + invokes the JIT entrypoint
# ============================================================================
echo -e "${BOLD}--- G2/G3: base.Dockerfile bakes entrypoint.sh ---${NC}"

if [[ ! -f "$BASE_DOCKERFILE" ]]; then
    fail "images/base.Dockerfile not found at $BASE_DOCKERFILE"
else
    if grep -qE '^COPY[[:space:]].*infra/scripts/entrypoint\.sh[[:space:]]+/home/runner/entrypoint\.sh' "$BASE_DOCKERFILE"; then
        pass "base.Dockerfile COPYs infra/scripts/entrypoint.sh to /home/runner/entrypoint.sh"
    else
        fail "base.Dockerfile does not COPY infra/scripts/entrypoint.sh to /home/runner/entrypoint.sh"
    fi

    if grep -qE '^ENTRYPOINT[[:space:]]+\["/home/runner/entrypoint\.sh"\]' "$BASE_DOCKERFILE"; then
        pass "base.Dockerfile sets ENTRYPOINT [\"/home/runner/entrypoint.sh\"]"
    else
        fail "base.Dockerfile does not set ENTRYPOINT [\"/home/runner/entrypoint.sh\"]"
    fi

    # The ENTRYPOINT must appear AFTER the COPY (order matters: setting it
    # before the file exists would still work in Docker, but we want the
    # COPY -> ENTRYPOINT ordering to stay a deliberate, readable sequence).
    copy_line=$(grep -nE '^COPY[[:space:]].*infra/scripts/entrypoint\.sh[[:space:]]+/home/runner/entrypoint\.sh' "$BASE_DOCKERFILE" | head -1 | cut -d: -f1)
    entrypoint_line=$(grep -nE '^ENTRYPOINT[[:space:]]+\["/home/runner/entrypoint\.sh"\]' "$BASE_DOCKERFILE" | head -1 | cut -d: -f1)
    if [[ -n "$copy_line" && -n "$entrypoint_line" && "$entrypoint_line" -gt "$copy_line" ]]; then
        pass "ENTRYPOINT declared after the entrypoint.sh COPY (line $copy_line -> $entrypoint_line)"
    else
        fail "ENTRYPOINT must be declared after the entrypoint.sh COPY (copy=$copy_line, entrypoint=$entrypoint_line)"
    fi

    # Must not run as root at the point the runner actually executes: USER
    # runner should appear before CMD (ENTRYPOINT itself doesn't care about
    # USER order in Dockerfile syntax, but we assert the image still ends
    # up running as the non-root runner user).
    if grep -qE '^USER[[:space:]]+runner[[:space:]]*$' "$BASE_DOCKERFILE"; then
        pass "base.Dockerfile still switches to USER runner"
    else
        fail "base.Dockerfile no longer sets USER runner"
    fi
fi
echo ""

# ============================================================================
# G8 — .gitignore ignores operator scope artifacts, keeps the template
# ============================================================================
echo -e "${BOLD}--- G8: .gitignore hygiene for infra/orchestrator/scopes/ ---${NC}"

if [[ ! -f "$GITIGNORE" ]]; then
    fail ".gitignore not found at $GITIGNORE"
else
    if grep -qxF 'infra/orchestrator/scopes/*' "$GITIGNORE"; then
        pass ".gitignore ignores infra/orchestrator/scopes/* (all operator artifacts)"
    else
        fail ".gitignore does not contain the blanket 'infra/orchestrator/scopes/*' rule"
    fi

    if grep -qxF '!infra/orchestrator/scopes/example.yml' "$GITIGNORE"; then
        pass ".gitignore re-includes infra/orchestrator/scopes/example.yml"
    else
        fail ".gitignore does not re-include infra/orchestrator/scopes/example.yml"
    fi

    # The old narrow '*.env'-only rule must be gone — it would leave
    # non-.env operator files (scope YAMLs, Dockerfiles, allowlist .txt
    # files) unignored, which is exactly the leak this fix closes.
    if grep -qxF 'infra/orchestrator/scopes/*.env' "$GITIGNORE"; then
        fail "the narrow 'infra/orchestrator/scopes/*.env' rule is still present (should be replaced by the blanket rule)"
    else
        pass "the narrow '*.env'-only rule has been replaced"
    fi
fi
echo ""

# ============================================================================
# G8 — behavioral check via git check-ignore (only when inside a git repo)
# ============================================================================
echo -e "${BOLD}--- G8: git check-ignore behavior ---${NC}"

if git -C "$RUNSECURE_ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    if git -C "$RUNSECURE_ROOT" check-ignore -q "infra/orchestrator/scopes/some-operator-scope.yml"; then
        pass "a hypothetical operator scope file (some-operator-scope.yml) is ignored"
    else
        fail "a hypothetical operator scope file (some-operator-scope.yml) is NOT ignored"
    fi

    if git -C "$RUNSECURE_ROOT" check-ignore -q "infra/orchestrator/scopes/some-operator.env"; then
        pass "a hypothetical operator .env file is ignored"
    else
        fail "a hypothetical operator .env file is NOT ignored"
    fi

    if git -C "$RUNSECURE_ROOT" check-ignore -q "infra/orchestrator/scopes/example.yml"; then
        fail "the tracked example.yml template is incorrectly ignored"
    else
        pass "the tracked example.yml template is NOT ignored"
    fi
else
    echo -e "  ${BOLD}SKIP${NC} not inside a git work tree — skipping check-ignore behavioral test"
fi
echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BOLD}=== Summary: ${PASS} passed, ${FAIL} failed ===${NC}\n"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
