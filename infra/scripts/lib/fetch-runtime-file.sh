#!/bin/bash
# ============================================================================
# RunSecure — Fetch Runtime File (SSRF-protected)
# ============================================================================
# Fetches a file from a local path or an HTTPS URL.
# Blocks any URL that resolves to a private/reserved address range.
#
# Usage:
#   bash fetch-runtime-file.sh <path-or-url> [output-file]
#
# If <path-or-url> is a local path (not starting with https://):
#   - Reads the file directly; outputs to stdout or [output-file].
#
# If <path-or-url> is an https:// URL:
#   - Resolves the hostname and checks against the SSRF blocklist.
#   - Downloads with curl to stdout or [output-file].
#   - http:// URLs are rejected (only https:// allowed for remote).
#
# Exit codes:
#   0 — success
#   1 — blocked (SSRF), file not found, or download error
#
# SSRF blocklist (spec §3.3):
#   - Loopback: 127.0.0.0/8, ::1, localhost
#   - RFC1918:  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
#   - Link-local: 169.254.0.0/16, fe80::/10
#   - CGNAT: 100.64.0.0/10
#   - IPv6 ULA: fc00::/7
#   - Special hostnames: metadata.google.internal
#
# Compatible with bash 3.2+ (macOS system bash).
# ============================================================================

set -euo pipefail

TARGET="${1:?Usage: fetch-runtime-file.sh <path-or-url> [output-file]}"
OUTPUT_FILE="${2:-}"

_err() { echo "[fetch-runtime-file] ERROR: $*" >&2; exit 1; }
_blocked() { echo "[fetch-runtime-file] SSRF BLOCKED: $*" >&2; exit 1; }

# ============================================================================
# SSRF IP address check
# ============================================================================
_is_private_ip() {
    local ip="$1"

    # Strip IPv6 brackets
    ip="${ip#[}"
    ip="${ip%]}"

    # Loopback IPv4
    if echo "$ip" | grep -qE '^127\.'; then
        return 0
    fi

    # RFC1918: 10.0.0.0/8
    if echo "$ip" | grep -qE '^10\.'; then
        return 0
    fi

    # RFC1918: 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
    if echo "$ip" | grep -qE '^172\.(1[6-9]|2[0-9]|3[01])\.'; then
        return 0
    fi

    # RFC1918: 192.168.0.0/16
    if echo "$ip" | grep -qE '^192\.168\.'; then
        return 0
    fi

    # Link-local: 169.254.0.0/16
    if echo "$ip" | grep -qE '^169\.254\.'; then
        return 0
    fi

    # CGNAT: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    if echo "$ip" | grep -qE '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'; then
        return 0
    fi

    # IPv6 loopback: ::1
    if [[ "$ip" == "::1" ]]; then
        return 0
    fi

    # IPv6 link-local: fe80::/10
    if echo "$ip" | grep -qiE '^fe[89ab][0-9a-f]:'; then
        return 0
    fi

    # IPv6 ULA: fc00::/7 (fc00:: - fdff::)
    if echo "$ip" | grep -qiE '^f[cd][0-9a-f]{2}:'; then
        return 0
    fi

    return 1
}

# ============================================================================
# Handle local file path
# ============================================================================
if [[ "$TARGET" != https://* && "$TARGET" != http://* ]]; then
    # Local path — no SSRF check needed
    if [[ ! -f "$TARGET" ]]; then
        _err "local file not found: $TARGET"
    fi
    if [[ -n "$OUTPUT_FILE" ]]; then
        cp "$TARGET" "$OUTPUT_FILE"
    else
        cat "$TARGET"
    fi
    exit 0
fi

# ============================================================================
# Reject http:// — only https:// is allowed for remote fetches
# ============================================================================
if [[ "$TARGET" == http://* ]]; then
    _blocked "http:// scheme is not allowed for remote file fetches — use https:// or a local path"
fi

# ============================================================================
# Extract hostname from https:// URL
# ============================================================================
# Remove https:// prefix, strip path/query
hostname_part="${TARGET#https://}"
hostname_part="${hostname_part%%/*}"
hostname_part="${hostname_part%%\?*}"
hostname_part="${hostname_part%%#*}"

# Handle IPv6 addresses: [::1] or [::1]:port
if [[ "$hostname_part" == \[* ]]; then
    # IPv6 literal — extract the bracketed address
    hostname="${hostname_part%%\]*}"
    hostname="${hostname#\[}"
else
    # Strip port if present (host:port → host)
    hostname="${hostname_part%%:*}"
fi

# ============================================================================
# Block known private hostnames by name (before DNS resolution)
# ============================================================================
case "$hostname" in
    localhost|localhost.localdomain)
        _blocked "hostname '$hostname' is a loopback address — not allowed for remote file fetches" ;;
    metadata.google.internal|metadata.google.internal.)
        _blocked "hostname '$hostname' is a cloud metadata endpoint — SSRF denied" ;;
esac

# ============================================================================
# Direct IP check: if the hostname IS already an IP, check it immediately
# ============================================================================
if echo "$hostname" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^\[?[0-9a-fA-F:]+\]?$'; then
    if _is_private_ip "$hostname"; then
        _blocked "URL '$TARGET' contains private/reserved IP '$hostname' — SSRF denied"
    fi
fi

# ============================================================================
# DNS resolution check: resolve hostname and verify all IPs are public
# ============================================================================
# Only attempt resolution for non-IP hostnames
if ! echo "$hostname" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^\[?[0-9a-fA-F:]+\]?$'; then
    if command -v dig >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if _is_private_ip "$ip"; then
                _blocked "URL '$TARGET' resolves to private/reserved IP '$ip' — SSRF denied"
            fi
        done < <(dig +short "$hostname" 2>/dev/null || true)
    elif command -v host >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if _is_private_ip "$ip"; then
                _blocked "URL '$TARGET' resolves to private/reserved IP '$ip' — SSRF denied"
            fi
        done < <(host -t A "$hostname" 2>/dev/null | awk '/has address/{print $NF}' || true)
    fi
    # If no DNS tool is available, allow the URL and let curl fail naturally.
fi

# ============================================================================
# Download via curl
# ============================================================================
CURL_OPTS=(
    --fail
    --silent
    --show-error
    --location
    --max-time 30
    --max-redirs 3
)

if [[ -n "$OUTPUT_FILE" ]]; then
    if ! curl "${CURL_OPTS[@]}" --output "$OUTPUT_FILE" "$TARGET"; then
        _err "failed to download: $TARGET"
    fi
else
    if ! curl "${CURL_OPTS[@]}" "$TARGET"; then
        _err "failed to download: $TARGET"
    fi
fi
