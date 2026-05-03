#!/bin/bash
# ============================================================================
# RunSecure — Job-Completed Hook
# ============================================================================
# Fires at the end of every job. Output appears in the workflow log as
# a "Job completed hook" step. Used for teardown summary + breadcrumbs
# the user might want at the end of a failing job.
#
# Same fail-safe contract as job-started.sh — must always exit 0.
# ============================================================================

trap 'exit 0' ERR
set -uo pipefail

_safe() { "$@" 2>/dev/null || true; }

echo "::group::RunSecure container — exit summary"
echo "Job ended:       $(_safe date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Memory peak:     $(_safe awk '/VmHWM/ {print $2 " " $3}' /proc/self/status)"
echo "Process count:   $(_safe ls /proc | grep -cE '^[0-9]+$')"
# Inspect /tmp for leftover artifacts (jobs that downloaded things)
TMP_FILES=$(_safe find /tmp -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
echo "/tmp entries:    ${TMP_FILES:-0}  (will be discarded — container is --rm)"
echo ""
echo "Container will exit and be destroyed. Worker log uploaded to GitHub."
echo "If logs show 'BlobNotFound', orchestrator's _diag/Worker_*.log has the full trace."
echo "::endgroup::"

exit 0
