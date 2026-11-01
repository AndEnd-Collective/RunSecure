#!/bin/bash
# Combine the per-architecture rust certification results into one verdict.
# Each certify leg writes RESULTS_DIR/certify-result-<slug> containing `pass`
# or `fail: <checks>`. Prints `certified=true` only when every listed
# architecture passed, `certified=false` when any certification check failed.
#
# A missing or malformed result is an infrastructure failure, not a rejected
# candidate, and exits non-zero.

set -euo pipefail

[[ $# -ge 2 ]] || {
    echo "Usage: $0 RESULTS_DIR SLUG [SLUG...]" >&2
    exit 2
}

RESULTS_DIR=$1
shift

CERTIFIED=true
for slug in "$@"; do
    result_file="${RESULTS_DIR}/certify-result-${slug}"
    [[ -f "$result_file" ]] || {
        echo "ERROR: no certification result for ${slug}" >&2
        exit 1
    }
    result=$(head -n 1 "$result_file")
    case "$result" in
        pass) ;;
        "fail: "?*) CERTIFIED=false ;;
        *)
            echo "ERROR: malformed certification result for ${slug}: '${result}'" >&2
            exit 1
            ;;
    esac
    echo "${slug}: ${result}" >&2
done

echo "certified=${CERTIFIED}"
