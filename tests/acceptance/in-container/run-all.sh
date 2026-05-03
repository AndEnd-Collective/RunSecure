#!/bin/bash
# ============================================================================
# RunSecure — In-Container Acceptance Test Driver
# ============================================================================
# Runs every check in checks/ inside the current container, aggregates
# results, and exits non-zero if any check failed.
#
# Each check is sourced (not executed in a subshell) so the lib.sh
# pass/fail counters carry across — but each check uses its own local
# accounting and prints a per-check subtotal. The driver counts
# "PASS:" / "FAIL:" lines in the combined output.
#
# Usage:
#   bash tests/acceptance/in-container/run-all.sh
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_DIR="${SCRIPT_DIR}/checks"

[ -d "$CHECKS_DIR" ] || { echo "ERROR: checks dir not found at $CHECKS_DIR" >&2; exit 2; }

echo ""
echo "============================================================================"
echo "RunSecure In-Container Acceptance Tests"
echo "  image: $(uname -a 2>/dev/null || echo unknown)"
echo "  user:  $(id 2>/dev/null || echo unknown)"
echo "  date:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================================"

OUTPUT_FILE=$(mktemp)
trap 'rm -f "$OUTPUT_FILE"' EXIT

for check in "$CHECKS_DIR"/*.sh; do
    [ -f "$check" ] || continue
    echo ""
    echo "--- $(basename "$check") ---"
    bash "$check" 2>&1 | tee -a "$OUTPUT_FILE"
done

# Aggregate
PASSES=$(grep -c '^PASS:' "$OUTPUT_FILE" || true)
FAILS=$(grep -c '^FAIL:' "$OUTPUT_FILE" || true)
SKIPS=$(grep -c '^SKIP:' "$OUTPUT_FILE" || true)

echo ""
echo "============================================================================"
echo "ACCEPTANCE RESULT — pass: $PASSES, fail: $FAILS, skip: $SKIPS"
echo "============================================================================"

if [ "$FAILS" -gt 0 ]; then
    echo ""
    echo "Failed checks:"
    grep '^FAIL:' "$OUTPUT_FILE" | head -20
    exit 1
fi
exit 0
