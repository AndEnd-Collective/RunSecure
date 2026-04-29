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
#   - Redirects are followed manually (max 3 hops) with an IP re-check at each hop.
#
# Exit codes:
#   0 — success
#   1 — blocked (SSRF), file not found, or download error
#
# SSRF blocklist (spec §3.3):
#   - This address:  0.0.0.0/8
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

_err()     { echo "[fetch-runtime-file] ERROR: $*" >&2; exit 1; }
_blocked() { echo "[fetch-runtime-file] SSRF BLOCKED: $*" >&2; exit 1; }

# ============================================================================
# SSRF IP address check
# ============================================================================
_is_private_ip() {
    local ip="$1"

    # Strip IPv6 brackets
    ip="${ip#[}"
    ip="${ip%]}"

    # 0.0.0.0/8 — "this" network (unspecified address)
    if echo "$ip" | grep -qE '^0\.'; then
        return 0
    fi

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

    # IPv4-mapped IPv6: ::ffff:N.N.N.N — recurse on the embedded IPv4 part
    if [[ "$ip" =~ ^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        _is_private_ip "${BASH_REMATCH[1]}" && return 0
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
# Extract hostname from an https:// URL (helper)
# ============================================================================
_extract_hostname() {
    local url="$1"
    local hostname_part host

    # Remove https:// prefix, strip path/query/fragment
    hostname_part="${url#https://}"
    hostname_part="${hostname_part%%/*}"
    hostname_part="${hostname_part%%\?*}"
    hostname_part="${hostname_part%%#*}"

    # Handle IPv6 addresses: [::1] or [::1]:port
    if [[ "$hostname_part" == \[* ]]; then
        host="${hostname_part%%\]*}"
        host="${host#\[}"
    else
        # Strip port if present (host:port → host)
        host="${hostname_part%%:*}"
    fi
    printf '%s' "$host"
}

# ============================================================================
# Resolve hostname and check all returned IPs against the SSRF blocklist.
# Exits with _blocked if any IP is private.
# ============================================================================
_check_host() {
    local hostname="$1"
    local url_for_msg="$2"

    # Block by name first
    case "$hostname" in
        localhost|localhost.localdomain)
            _blocked "hostname '$hostname' is a loopback address — not allowed for remote file fetches" ;;
        metadata.google.internal|metadata.google.internal.)
            _blocked "hostname '$hostname' is a cloud metadata endpoint — SSRF denied" ;;
    esac

    # If the hostname IS an IP literal, check it directly.
    # The alternation covers: pure IPv4, pure IPv6 (hex+colons), and the
    # mixed IPv4-mapped IPv6 form (::ffff:N.N.N.N) which contains both
    # colons and dots.
    if echo "$hostname" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^\[?[0-9a-fA-F:]+\]?$|^\[?[0-9a-fA-F:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]?$'; then
        if _is_private_ip "$hostname"; then
            _blocked "URL '$url_for_msg' contains private/reserved IP '$hostname' — SSRF denied"
        fi
        return 0
    fi

    # DNS resolution check — verify every returned IP is public
    if command -v dig >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if _is_private_ip "$ip"; then
                _blocked "URL '$url_for_msg' resolves to private/reserved IP '$ip' — SSRF denied"
            fi
        done < <(dig +short "$hostname" 2>/dev/null || true)
    elif command -v host >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if _is_private_ip "$ip"; then
                _blocked "URL '$url_for_msg' resolves to private/reserved IP '$ip' — SSRF denied"
            fi
        done < <(host -t A "$hostname" 2>/dev/null | awk '/has address/{print $NF}' || true)
    fi
    # If no DNS tool is available, allow the URL and let curl fail naturally.
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
# Manual redirect loop — re-check IP at each hop (max 3 hops)
# This prevents SSRF via 302 redirect to a private IP.
# ============================================================================
_fetch_with_ssrf_redirect_check() {
    local url="$1"
    local out_file="$2"  # may be empty (means stdout)
    local max_hops=3
    local hop=0
    local header_file
    header_file=$(mktemp /tmp/runsecure-hdr-XXXXXX)
    local body_file
    body_file=$(mktemp /tmp/runsecure-body-XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -f '${header_file}' '${body_file}'" RETURN

    while (( hop < max_hops )); do
        # Must still be https://
        if [[ "$url" != https://* ]]; then
            _blocked "redirect to non-HTTPS URL '$url' — only https:// is allowed"
        fi

        local hostname
        hostname=$(_extract_hostname "$url")
        _check_host "$hostname" "$url"

        # Fetch: do NOT follow redirects automatically (--max-redirs 0)
        local http_code
        http_code=$(curl \
            --fail-with-body \
            --silent \
            --show-error \
            --max-redirs 0 \
            --max-time 30 \
            --dump-header "${header_file}" \
            --output "${body_file}" \
            --write-out '%{http_code}' \
            "$url" 2>/dev/null || true)

        # 2xx — success
        if [[ "$http_code" =~ ^2 ]]; then
            if [[ -n "$out_file" ]]; then
                cp "${body_file}" "$out_file"
            else
                cat "${body_file}"
            fi
            return 0
        fi

        # 3xx — check Location header and loop
        if [[ "$http_code" =~ ^3 ]]; then
            local location
            location=$(grep -i '^[Ll]ocation:' "${header_file}" | tail -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')
            if [[ -z "$location" ]]; then
                _err "redirect (HTTP $http_code) with no Location header from '$url'"
            fi

            # Resolve relative redirects to absolute
            if [[ "$location" != http://* && "$location" != https://* ]]; then
                # Relative redirect — prefix with base URL
                local base="${url%%//*}//${url#*//}"
                base="${base%%/*}"
                location="${base}/${location#/}"
            fi

            url="$location"
            hop=$(( hop + 1 ))
            continue
        fi

        # Non-2xx / non-3xx failure
        _err "HTTP $http_code from '$url'"
    done

    _err "too many redirects (>${max_hops}) following '$1'"
}

_fetch_with_ssrf_redirect_check "$TARGET" "$OUTPUT_FILE"
