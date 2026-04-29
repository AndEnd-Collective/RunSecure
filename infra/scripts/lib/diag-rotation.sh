#!/bin/bash
# ============================================================================
# RunSecure — Diag Directory Rotation Helper
# ============================================================================
# Rotates _diag/ and _diag-proxy/ between runs:
#   - At start of each run.sh invocation, move _diag/ -> _diag.previous/
#     and _diag-proxy/ -> _diag-proxy.previous/ (overwriting prior).
#   - Acquires an flock on a stable lockfile so concurrent invocations
#     serialize on the rotate step.
#
# When RUNSECURE_DIAG_RETENTION=0 in the environment, no rotation is
# performed (the bind mount is also skipped — see run.sh).
#
# Sourced by infra/scripts/run.sh.
# ============================================================================

# Note: this file is sourced. Do NOT use `set -euo pipefail` here — that
# would change the caller's shell options. Each function handles its own
# errors.

# ----------------------------------------------------------------------------
# rotate_one_dir <dir>
#
# If <dir> exists and is non-empty, move its contents to <dir>.previous/,
# overwriting any previous contents. If <dir> does not exist, create it
# with UID 1001 ownership.
# ----------------------------------------------------------------------------
rotate_one_dir() {
    local dir="$1"
    local previous="${dir}.previous"

    mkdir -p "$(dirname "$dir")"

    local has_content=false
    if [[ -d "$dir" ]]; then
        local f
        # Iterate regular files, hidden files (excluding . and ..), and deeper
        # hidden names. Each glob may expand to its literal string when there
        # are no matches; the [[ -e ]] guard discards those non-matches safely.
        for f in "$dir"/* "$dir"/.[!.]*; do
            # skip glob non-matches
            [[ -e "$f" ]] || continue
            has_content=true
            break
        done
    fi
    if [[ "$has_content" == true ]]; then
        rm -rf "$previous"
        mv "$dir" "$previous"
    fi

    mkdir -p "$dir"
    chown 1001:0 "$dir" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# rotate_diag_dirs <repo_root>
#
# Rotate both _diag/ and _diag-proxy/. Honors RUNSECURE_DIAG_RETENTION=0.
# Serializes concurrent invocations via flock on <repo_root>/_diag/.rotate.lock.
# ----------------------------------------------------------------------------
rotate_diag_dirs() {
    local repo_root="$1"

    if [[ "${RUNSECURE_DIAG_RETENTION:-1}" == "0" ]]; then
        echo "[RunSecure] RUNSECURE_DIAG_RETENTION=0 — skipping diag rotation."
        return 0
    fi

    # Lockfile lives OUTSIDE any rotated directory so that renaming _diag/ to
    # _diag.previous/ does not move the inode and break concurrent serialization.
    local lockfile="$repo_root/.diag-rotate.lock"
    mkdir -p "$repo_root"
    touch "$lockfile" 2>/dev/null || true

    if command -v flock >/dev/null 2>&1; then
        (
            flock -x 9
            rotate_one_dir "$repo_root/_diag"
            rotate_one_dir "$repo_root/_diag-proxy"
        ) 9>"$lockfile"
    else
        # macOS / minimal envs: no flock available. Warn and proceed without
        # serialization — concurrent invocations may interleave rotation.
        echo "[RunSecure] WARNING: flock not available — concurrent diag rotation is not serialized." >&2
        rotate_one_dir "$repo_root/_diag"
        rotate_one_dir "$repo_root/_diag-proxy"
    fi
}
