#!/bin/bash
# Delete superseded bot branches from origin. Each weekly dependency refresh
# starts from main, so an older bot/<kind>-v* branch carries nothing the newest
# one lacks. Keep the current branch and any branch with an open PR; a failed
# open-PR lookup aborts before anything is deleted.

set -euo pipefail

usage() {
    echo "Usage: $0 PREFIX KEEP_BRANCH   (e.g. bot/go-deps- bot/go-deps-v2.3.0)" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage

PREFIX=$1
KEEP=$2

[[ "$PREFIX" =~ ^bot/[a-z0-9][a-z0-9-]*-$ ]] || {
    echo "ERROR: prefix must look like bot/<kind>- : '$PREFIX'" >&2
    exit 1
}

HEADS=$(git ls-remote --heads origin "refs/heads/${PREFIX}*")

# Decide every branch before deleting any, so a lookup failure deletes nothing.
STALE=()
while read -r _ ref; do
    [[ -n "$ref" ]] || continue
    branch=${ref#refs/heads/}
    [[ "$branch" != "$KEEP" ]] || continue
    open=$(gh pr list --head "$branch" --state open --json number --jq length)
    if [[ "$open" == 0 ]]; then
        STALE+=("$branch")
    else
        echo "keeping $branch: open pull request"
    fi
done <<< "$HEADS"

if [[ ${#STALE[@]} -eq 0 ]]; then
    echo "no superseded ${PREFIX}* branches"
    exit 0
fi
git push origin --delete "${STALE[@]}"
echo "pruned ${#STALE[@]} superseded ${PREFIX}* branch(es): ${STALE[*]}"
