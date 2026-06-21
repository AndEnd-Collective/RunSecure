#!/usr/bin/env bash
# =============================================================================
# tests/validation/test-go-coverage.sh
#
# Enforces the RunSecure Go coverage policy:
#
#   "Logic packages (internal/*) ≥99% by unit tests.
#    Composition roots (cmd/orchestrator, cmd/socket-proxy) are exercised by
#    binary integration instrumentation in
#    tests/integration/orchestrator/coverage.sh — not by this script."
#
# This script:
#   1. Runs 'go test ./...' for both Go modules.
#   2. Asserts that EVERY package EXCEPT the explicitly allowlisted cmd packages
#      has ≥99% statement coverage.
#   3. Asserts that the integration coverage script exists (documents the gate).
#   4. Prints a summary and exits non-zero if any assertion fails.
#
# Allowlisted packages (covered by integration tests, not unit tests):
#   github.com/AndEnd-Collective/runsecure/infra/orchestrator/cmd/orchestrator
#   github.com/AndEnd-Collective/runsecure/infra/socket-proxy/cmd/socket-proxy
#
# Packages with no statements (backend interface package) pass automatically.
#
# Usage:
#   bash tests/validation/test-go-coverage.sh
#   UNIT_THRESHOLD=99 bash tests/validation/test-go-coverage.sh
#
# Exit codes:
#   0  — all assertions pass
#   1  — one or more logic packages are below threshold
#   2  — integration coverage script missing
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ORCH_MODULE="${REPO_ROOT}/infra/orchestrator"
PROXY_MODULE="${REPO_ROOT}/infra/socket-proxy"
INT_COV_SCRIPT="${REPO_ROOT}/tests/integration/orchestrator/coverage.sh"

# Minimum statement coverage required for all logic (non-cmd) packages.
UNIT_THRESHOLD="${UNIT_THRESHOLD:-99}"

# Packages whose composition-root functions are intentionally excluded from
# unit-test coverage — they are exercised by tests/integration/orchestrator/coverage.sh.
ALLOWLISTED_PKGS=(
  "github.com/AndEnd-Collective/runsecure/infra/orchestrator/cmd/orchestrator"
  "github.com/AndEnd-Collective/runsecure/infra/socket-proxy/cmd/socket-proxy"
)

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf "${GREEN}  PASS${NC}  %s\n" "$*"; }
fail() { printf "${RED}  FAIL${NC}  %s\n" "$*"; }
info() { printf "${BOLD}[gate]${NC} %s\n" "$*"; }
skip() { printf "${YELLOW}  SKIP${NC}  %s\n" "$*"; }

OVERALL_FAIL=0

# ---------------------------------------------------------------------------
# Helper: is_allowlisted <pkg>
# ---------------------------------------------------------------------------
is_allowlisted() {
  local pkg="$1"
  for a in "${ALLOWLISTED_PKGS[@]}"; do
    [[ "$pkg" == "$a" ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# Helper: check_module <module_dir> <module_name>
# Runs 'go test ./... -coverprofile' for the module, then asserts every
# non-allowlisted package meets the threshold.
# ---------------------------------------------------------------------------
check_module() {
  local mod_dir="$1"
  local mod_name="$2"
  local coverfile
  coverfile="$(mktemp /tmp/go-cov-XXXXXX.out)"

  info "Testing ${mod_name} (dir: ${mod_dir})"

  if ! (cd "$mod_dir" && go test ./... \
        -covermode=atomic \
        -coverprofile="$coverfile" \
        -count=1 \
        >/dev/null 2>&1); then
    fail "${mod_name}: 'go test ./...' failed"
    OVERALL_FAIL=1
    rm -f "$coverfile"
    return
  fi

  # Parse per-package coverage from the cover profile.
  # 'go tool cover -func' output: <file>:<line>: <fn>  <pct>%
  # The last line for each package is NOT labeled — we need per-package totals.
  # Strategy: run 'go test -v ./pkg/...' with -coverprofile per package, or
  # use the per-package output from 'go test ./... -v -cover'.
  # Simpler: use 'go test ./... -cover' output directly (not the profile file).

  local per_pkg_output
  per_pkg_output=$(cd "$mod_dir" && go test ./... -cover -count=1 2>&1) || true

  local module_fail=0

  while IFS= read -r line; do
    # Lines look like:
    #   ok    github.com/.../pkg    0.123s  coverage: 99.7% of statements
    #   ok    github.com/.../pkg    0.456s  coverage: [no statements]
    #   FAIL  github.com/.../pkg    [build failed]
    if [[ "$line" =~ ^(ok|FAIL)[[:space:]]+(github\.com[^[:space:]]+)[[:space:]] ]]; then
      local pkg="${BASH_REMATCH[2]}"
      local cov_pct="0"

      if [[ "$line" =~ coverage:[[:space:]]([0-9]+\.[0-9]+)% ]]; then
        cov_pct="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ "no statements" ]]; then
        # No statements → counts as 100% (nothing to cover).
        cov_pct="100"
      fi

      local cov_int="${cov_pct%%.*}"

      if is_allowlisted "$pkg"; then
        skip "${pkg}  ${cov_pct}% (allowlisted — covered by integration test)"
      elif [[ "$cov_int" -ge "$UNIT_THRESHOLD" ]]; then
        ok "${pkg}  ${cov_pct}%"
      else
        fail "${pkg}  ${cov_pct}% < ${UNIT_THRESHOLD}%"
        module_fail=1
        OVERALL_FAIL=1
      fi
    fi
  done <<< "$per_pkg_output"

  rm -f "$coverfile"

  if [[ "$module_fail" -eq 0 ]]; then
    ok "${mod_name}: all logic packages ≥${UNIT_THRESHOLD}%"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
printf "\n${BOLD}═══════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  RunSecure Go Unit Coverage Gate${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════${NC}\n"
printf "\n"
printf "  Policy: logic packages ≥%d%%; composition roots (cmd/*) allowlisted.\n" "$UNIT_THRESHOLD"
printf "\n"

# Gate 1: Integration coverage script must exist.
info "Checking integration coverage script exists …"
if [[ -x "$INT_COV_SCRIPT" ]]; then
  ok "Integration coverage script present: tests/integration/orchestrator/coverage.sh"
else
  fail "Integration coverage script missing or not executable: $INT_COV_SCRIPT"
  fail "Create tests/integration/orchestrator/coverage.sh to satisfy the coverage gate."
  OVERALL_FAIL=1
fi
printf "\n"

# Gate 2: Check orchestrator module.
info "Orchestrator module"
check_module "$ORCH_MODULE" "infra/orchestrator"
printf "\n"

# Gate 3: Check socket-proxy module.
info "Socket-proxy module"
check_module "$PROXY_MODULE" "infra/socket-proxy"
printf "\n"

# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------
printf "${BOLD}═══════════════════════════════════════════════════════${NC}\n"
if [[ "$OVERALL_FAIL" -eq 0 ]]; then
  printf "${GREEN}${BOLD}PASS${NC} — all logic packages ≥%d%% and integration coverage script present.\n\n" "$UNIT_THRESHOLD"
  exit 0
else
  printf "${RED}${BOLD}FAIL${NC} — one or more assertions failed (see above).\n\n"
  exit 1
fi
