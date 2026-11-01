#!/bin/bash
# ============================================================================
# RunSecure Unit Test — run.sh idle exit and runner deregistration
# ============================================================================
# The one-shot self-runner must exit once a launched runner claims no job
# within --idle-timeout, and must never leave a runner registered on GitHub
# when it stops — whether by idle release or by `kill`.
#
# Runs the real run.sh from a sandbox copy whose sibling scripts are stubbed,
# with `docker` and `gh` stubs on PATH that model the runner API: the JIT
# request, the runner's busy flag, and GitHub refusing to delete a busy runner.
#
# Prerequisites: yq, jq
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
# expect DESCRIPTION COMMAND... — pass when COMMAND succeeds.
expect() { local desc=$1; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
not() { ! "$@"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SANDBOX="$WORK/runsecure"
mkdir -p "$SANDBOX/infra/scripts/lib" "$WORK/bin" "$WORK/project/.github"
cp "$RUNSECURE_ROOT/infra/scripts/run.sh" "$SANDBOX/infra/scripts/run.sh"
: > "$SANDBOX/infra/docker-compose.yml"
printf '#!/bin/bash\necho runsecure-test:local\n' > "$SANDBOX/infra/scripts/compose-image.sh"
printf '#!/bin/bash\n: > "%s/infra/runtime-compose.yml"\n' "$SANDBOX" > "$SANDBOX/infra/scripts/generate-egress-conf.sh"
printf 'rotate_diag_dirs() { :; }\n' > "$SANDBOX/infra/scripts/lib/diag-rotation.sh"
chmod +x "$SANDBOX/infra/scripts/"*.sh

cat > "$WORK/project/.github/runner.yml" <<'YAML'
runtime: node:24
tools: []
http_egress: []
YAML

# docker: `compose up` is the runner. STUB_JOB=idle never finishes (no job is
# ever assigned); STUB_JOB=job finishes after STUB_JOB_SECONDS.
cat > "$WORK/bin/docker" <<'STUB'
#!/bin/bash
case " $* " in
    *" compose version "*|*" image inspect "*) exit 0 ;;
    *" up "*)
        echo up >> "$STUB_LOG"
        if [[ "$STUB_JOB" == idle ]]; then exec sleep 3017; fi
        sleep "${STUB_JOB_SECONDS:-1}"
        exit 0
        ;;
    *" down "*) echo down >> "$STUB_LOG"; exit 0 ;;
esac
exit 0
STUB

# gh: STUB_BUSY is the runner's busy flag; STUB_DELETE=refuse models GitHub
# rejecting deletion of a runner that was just assigned a job.
cat > "$WORK/bin/gh" <<'STUB'
#!/bin/bash
case " $* " in
    *" auth status "*) exit 0 ;;
    *"generate-jitconfig"*)
        echo jit >> "$STUB_LOG"
        echo '{"runner":{"id":4242},"encoded_jit_config":"jit-config"}'
        ;;
    *" -X DELETE "*)
        [[ "${STUB_DELETE:-}" == refuse ]] && { echo "Runner is busy" >&2; exit 1; }
        echo "delete ${*: -1}" >> "$STUB_LOG"
        ;;
    *"--jq .busy"*) echo "${STUB_BUSY:-false}" ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/docker" "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"

REPO="testowner/idle-exit-$$"
LOCK_PATH="${TMPDIR:-/tmp}/runsecure-idle-exit-$$.lock"
RUN="$SANDBOX/infra/scripts/run.sh"

# Run run.sh with a hard deadline so a regression fails instead of hanging.
run_with_deadline() {
    local deadline=$1; shift
    "$RUN" --project "$WORK/project" --repo "$REPO" "$@" > "$WORK/out" 2>&1 &
    local pid=$! elapsed=0
    while kill -0 "$pid" 2>/dev/null && [[ $elapsed -lt $deadline ]]; do
        sleep 1
        elapsed=$((elapsed + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null
        pkill -f "sleep 3017" 2>/dev/null
        RC=124
    else
        wait "$pid"
        RC=$?
    fi
}

count() { grep -c "^$1" "$STUB_LOG" 2>/dev/null || true; }
runner_alive() { pgrep -f "sleep 3017" >/dev/null; }

echo -e "\n${BOLD}=== run.sh idle exit and deregistration ===${NC}\n"

echo -e "${BOLD}--- 1. idle runner is released and the orchestrator exits ---${NC}"
export STUB_LOG="$WORK/log1" STUB_JOB=idle STUB_BUSY=false STUB_DELETE=""
run_with_deadline 40 --max-jobs 3 --idle-timeout 1
expect "exits 0 instead of waiting forever (rc=$RC)" test $RC -eq 0
expect "stops after the idle slot rather than requesting more runners" test "$(count jit)" -eq 1
expect "deletes the idle runner's GitHub registration" grep -qx "delete repos/$REPO/actions/runners/4242" "$STUB_LOG"
expect "reports why it exited" grep -q "No job claimed within 1s" "$WORK/out"
expect "releases the orchestrator lock" not test -d "$LOCK_PATH"

echo -e "\n${BOLD}--- 2. runners that claim jobs run to completion ---${NC}"
export STUB_LOG="$WORK/log2" STUB_JOB=job STUB_JOB_SECONDS=1 STUB_BUSY=true
run_with_deadline 40 --max-jobs 2 --idle-timeout 1
expect "exits 0 (rc=$RC)" test $RC -eq 0
expect "processes every requested job" test "$(count jit)" -eq 2
expect "finishes through the normal path" grep -q "All jobs processed" "$WORK/out"
expect "never releases a busy runner" not grep -q "No job claimed" "$WORK/out"

echo -e "\n${BOLD}--- 3. a job assigned at the deadline still runs ---${NC}"
export STUB_LOG="$WORK/log3" STUB_JOB=job STUB_JOB_SECONDS=8 STUB_BUSY=false STUB_DELETE=refuse
run_with_deadline 40 --max-jobs 1 --idle-timeout 1
expect "exits 0 (rc=$RC)" test $RC -eq 0
expect "waits for the job when GitHub refuses the delete" grep -q "All jobs processed" "$WORK/out"
expect "does not report an idle release" not grep -q "No job claimed" "$WORK/out"

echo -e "\n${BOLD}--- 4. kill tears down and deregisters ---${NC}"
export STUB_LOG="$WORK/log4" STUB_JOB=idle STUB_BUSY=false STUB_DELETE=""
"$RUN" --project "$WORK/project" --repo "$REPO" --max-jobs 2 > "$WORK/out" 2>&1 &
PID=$!
for _ in $(seq 1 20); do [[ "$(count up)" -ge 1 ]] && break; sleep 0.5; done
kill -TERM "$PID"
for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
expect "exits promptly on SIGTERM" not kill -0 "$PID" 2>/dev/null
kill -9 "$PID" 2>/dev/null
expect "deletes the in-flight runner registration" grep -qx "delete repos/$REPO/actions/runners/4242" "$STUB_LOG"
expect "tears down the compose project" grep -qx down "$STUB_LOG"
expect "leaves no runner process behind" not runner_alive
pkill -f "sleep 3017" 2>/dev/null
expect "releases the orchestrator lock" not test -d "$LOCK_PATH"

echo -e "\n${BOLD}--- 5. --idle-timeout is validated ---${NC}"
OUTPUT=$("$RUN" --project "$WORK/project" --repo "$REPO" --idle-timeout soon 2>&1 || true)
expect "rejects a non-numeric timeout" grep -q "idle-timeout must be a whole number" <<< "$OUTPUT"

echo ""
echo -e "${BOLD}=== Summary ===${NC}"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""
[[ $PASS -gt 0 && $FAIL -eq 0 ]]
