#!/bin/bash
# ============================================================================
# RunSecure — Acceptance Test Library
# ============================================================================
# Helper functions for in-container acceptance checks. Each check sources
# this and uses pass/fail/expect_fail. The driver (run-all.sh) parses the
# output to aggregate results.
#
# Output contract (machine-readable):
#   PASS: <claim-id> <description>
#   FAIL: <claim-id> <description>
#   SKIP: <claim-id> <description> — <reason>
#
# claim-id format: H<n> for hardening, R<n> for runtime, N<n> for network
# (matching the Layer numbering in SECURITY.md).
# ============================================================================

set -uo pipefail

_PASS_COUNT=0
_FAIL_COUNT=0

pass() {
    local claim="$1"; shift
    printf 'PASS: %s %s\n' "$claim" "$*"
    _PASS_COUNT=$((_PASS_COUNT + 1))
}

fail() {
    local claim="$1"; shift
    printf 'FAIL: %s %s\n' "$claim" "$*" >&2
    _FAIL_COUNT=$((_FAIL_COUNT + 1))
}

skip() {
    local claim="$1"; shift
    local reason="$1"; shift
    printf 'SKIP: %s %s — %s\n' "$claim" "$*" "$reason"
}

# expect_fail <claim> <description> -- <command...>
# Asserts that the command FAILS (non-zero exit). Used for security
# properties: "trying to do X must fail."
expect_fail() {
    local claim="$1"; shift
    local desc="$1"; shift
    [ "$1" = "--" ] && shift
    if "$@" >/dev/null 2>&1; then
        fail "$claim" "$desc — command unexpectedly succeeded: $*"
    else
        pass "$claim" "$desc"
    fi
}

# expect_pass <claim> <description> -- <command...>
expect_pass() {
    local claim="$1"; shift
    local desc="$1"; shift
    [ "$1" = "--" ] && shift
    if "$@" >/dev/null 2>&1; then
        pass "$claim" "$desc"
    else
        fail "$claim" "$desc — command failed: $*"
    fi
}

# Print summary at end of a check file
summary() {
    printf '\n--- subtotal: %d pass, %d fail ---\n' "$_PASS_COUNT" "$_FAIL_COUNT"
    [ "$_FAIL_COUNT" -eq 0 ]
}
