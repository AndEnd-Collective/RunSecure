#!/bin/bash
# ============================================================================
# RunSecure — merge-pr-when-green.sh merges only an all-green pull request
# ============================================================================
# The weekly automation merges its own pull requests with no human in the
# loop, so this script is the only thing between a failing check and main.
# gh is stubbed with a scripted sequence of check states; the test asserts
# when a merge happens and, more importantly, when it must not.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MERGER="${RUNSECURE_ROOT}/infra/scripts/merge-pr-when-green.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-merge-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# The stub serves one line of $STATES per `gh pr checks` poll (repeating the
# last line once exhausted) and records a merge instead of performing it.
mkdir -p "${tmp}/bin"
cat > "${tmp}/bin/gh" <<'STUB'
#!/bin/bash
set -euo pipefail
if [[ "$1 $2" == "pr merge" ]]; then
  echo "$*" >> "${STUB_DIR}/merged"
  exit 0
fi
if [[ "$1 $2" == "pr checks" ]]; then
  # A --jq call is the failed-name lookup, not a poll: answer from the
  # current state without advancing the sequence.
  advance=true
  for argument in "$@"; do
    [[ "$argument" == "--jq" ]] && advance=false
  done
  index=$(cat "${STUB_DIR}/index")
  total=$(wc -l < "${STUB_DIR}/states" | tr -d ' ')
  line=$(( index < total ? index : total ))
  state=$(sed -n "${line}p" "${STUB_DIR}/states")
  if [[ "$advance" == true ]]; then
    echo $(( index + 1 )) > "${STUB_DIR}/index"
  fi
  json='['
  separator=''
  number=0
  for bucket in $state; do
    number=$(( number + 1 ))
    json+="${separator}{\"name\":\"check-${number}\",\"bucket\":\"${bucket}\"}"
    separator=','
  done
  json+=']'
  if [[ "$advance" == true ]]; then
    printf '%s\n' "$json"
  else
    jq -r '.[] | select(.bucket == "fail" or .bucket == "cancel") | .name' <<<"$json"
  fi
  # Like the real command: non-zero unless every check passed.
  [[ "$state" != *pending* && "$state" != *fail* && "$state" != *cancel* && -n "$state" ]]
  exit $?
fi
exit 1
STUB
chmod +x "${tmp}/bin/gh"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# run_case NAME MIN_CHECKS EXPECT(merged|refused) STATE_LINE...
run_case() {
    local name="$1" min_checks="$2" expect="$3"
    shift 3
    local dir="${tmp}/case"
    rm -rf "$dir"
    mkdir -p "$dir"
    printf '%s\n' "$@" > "${dir}/states"
    echo 1 > "${dir}/index"
    local status=0
    env PATH="${tmp}/bin:${PATH}" STUB_DIR="$dir" \
        POLL_SECONDS=0 SETTLE_SECONDS=0 TIMEOUT_SECONDS=1 \
        bash "$MERGER" "https://github.example/pull/7" "$min_checks" > "${dir}/out" 2>&1 || status=$?
    local merged=false
    [[ -f "${dir}/merged" ]] && merged=true
    if [[ "$expect" == merged && "$status" -eq 0 && "$merged" == true ]] \
        && grep -q -- '--squash --delete-branch' "${dir}/merged"; then
        pass "$name"
    elif [[ "$expect" == refused && "$status" -ne 0 && "$merged" == false ]]; then
        pass "$name"
    else
        fail "$name (exit=${status}, merged=${merged}): $(tail -2 "${dir}/out" | tr '\n' ' ')"
    fi
}

run_case "merges when every check passed" 4 merged \
    "pass pass pass pass"
run_case "waits out pending checks, then merges" 4 merged \
    "pending pending pending pending" "pass pending pass pass" "pass pass pass pass"
run_case "skipped checks do not block a merge" 3 merged \
    "pass skipping pass pass"
run_case "refuses when a check failed" 4 refused \
    "pass fail pass pass"
run_case "refuses when a check was cancelled" 4 refused \
    "pass pass cancel pass"
run_case "refuses when a failure appears after pending" 4 refused \
    "pending pending pending pending" "pass pass fail pending"
run_case "refuses when no checks ever report" 4 refused \
    ""
run_case "refuses when fewer checks than required reported" 4 refused \
    "pass pass"
run_case "refuses when checks never finish" 4 refused \
    "pass pending pass pass"
# All green on the first look, a late check failing on the confirming look:
# the second look must be the one that decides.
run_case "refuses when a late-registered check fails on the confirming look" 4 refused \
    "pass pass pass pass" "pass pass pass pass fail"
run_case "keeps waiting when a late-registered check is still pending" 4 merged \
    "pass pass pass pass" "pass pass pass pass pending" "pass pass pass pass pass" "pass pass pass pass pass"

if env PATH="${tmp}/bin:${PATH}" bash "$MERGER" 7 0 >/dev/null 2>&1 \
    || env PATH="${tmp}/bin:${PATH}" bash "$MERGER" 7 many >/dev/null 2>&1; then
    fail "rejects a MIN_CHECKS that is not a positive integer"
else
    pass "rejects a MIN_CHECKS that is not a positive integer"
fi

echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
fi
echo "PASSED: $PASS tests"
