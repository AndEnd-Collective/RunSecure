#!/bin/bash
# ============================================================================
# RunSecure — merge a pull request once every one of its checks has passed
# ============================================================================
# The weekly automation opens pull requests (Go dependency refresh, Rust
# toolchain pin). They used to sit open until a person approved their
# workflow runs and pressed merge, which is how a dependency refresh for one
# release was still open when the next one was cut. This script is the last
# step of that automation: it waits for the pull request's checks and merges
# it, with no human in the loop. CI is the gate.
#
# It merges only when:
#   - at least MIN_CHECKS checks have reported (so "no checks yet" is never
#     mistaken for "nothing failed"),
#   - none of them failed or was cancelled,
#   - none is still pending,
#   - and the same holds on a second look after SETTLE_SECONDS, which catches
#     a workflow that registered its checks late.
#
# Anything else exits non-zero and leaves the pull request open.
#
# Usage: merge-pr-when-green.sh PR MIN_CHECKS
#   PR          pull request URL or number (needs GH_TOKEN, and GH_REPO when
#               a number is given)
#   MIN_CHECKS  how many checks must have reported before a merge
#
# Environment (all optional):
#   POLL_SECONDS             seconds between polls           (default 30)
#   TIMEOUT_SECONDS          give up after this long         (default 5400)
#   SETTLE_SECONDS           pause before the confirming look (default 60)
#   OPTIONAL_PENDING_CHECKS  comma-separated check names that do not have to
#                            finish. A check named here is left out while it
#                            is pending; once it reports, it counts like any
#                            other, so a failure still blocks the merge.
#                            Meant for `lints-on-self`, which queues for a
#                            self-hosted runner that is only online when an
#                            operator starts one, and repeats lints that
#                            validate.yml already runs on a hosted runner.
# ============================================================================

set -euo pipefail

PR="${1:?Usage: merge-pr-when-green.sh PR MIN_CHECKS}"
MIN_CHECKS="${2:?Usage: merge-pr-when-green.sh PR MIN_CHECKS}"
POLL_SECONDS="${POLL_SECONDS:-30}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5400}"
SETTLE_SECONDS="${SETTLE_SECONDS:-60}"
OPTIONAL_PENDING_CHECKS="${OPTIONAL_PENDING_CHECKS:-}"

if [[ ! "$MIN_CHECKS" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::MIN_CHECKS must be a positive integer, got '${MIN_CHECKS}'" >&2
    exit 2
fi

# Prints "<total> <pending> <failed>" for the pull request's checks.
# `gh pr checks` exits non-zero while checks are pending or failed, and when
# there are none yet, so its status is not used; only its JSON is.
tally() {
    local json
    json=$(gh pr checks "$PR" --json name,bucket 2>/dev/null) || true
    if [[ -z "$json" ]]; then
        json='[]'
    fi
    jq -r --arg optional "$OPTIONAL_PENDING_CHECKS" '
        ($optional | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))) as $names
        | map(select((.bucket == "pending" and (.name as $n | $names | index($n))) | not))
        | [
            length,
            (map(select(.bucket == "pending")) | length),
            (map(select(.bucket == "fail" or .bucket == "cancel")) | length)
          ] | @tsv' <<<"$json"
}

failed_names() {
    gh pr checks "$PR" --json name,bucket \
        --jq '.[] | select(.bucket == "fail" or .bucket == "cancel") | .name' 2>/dev/null || true
}

deadline=$((SECONDS + TIMEOUT_SECONDS))
confirmed=false
while :; do
    read -r total pending failed < <(tally)
    echo "checks: total=${total} pending=${pending} failed=${failed}"

    if [[ "$failed" -gt 0 ]]; then
        echo "::error title=Automatic merge refused::${failed} check(s) failed on ${PR}: $(failed_names | tr '\n' ' ')"
        exit 1
    fi

    if [[ "$total" -ge "$MIN_CHECKS" && "$pending" -eq 0 ]]; then
        if [[ "$confirmed" == true ]]; then
            break
        fi
        # Look again after a pause before trusting an all-green result.
        confirmed=true
        sleep "$SETTLE_SECONDS"
        continue
    fi
    confirmed=false

    if [[ "$SECONDS" -ge "$deadline" ]]; then
        echo "::error title=Automatic merge timed out::${PR} still has ${pending} pending check(s) and ${total} of the required ${MIN_CHECKS} reported after ${TIMEOUT_SECONDS}s."
        exit 1
    fi
    sleep "$POLL_SECONDS"
done

echo "All ${total} checks passed; merging ${PR}."
gh pr merge "$PR" --squash --delete-branch
