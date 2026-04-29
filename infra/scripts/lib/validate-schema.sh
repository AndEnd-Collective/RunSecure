#!/bin/bash
# ============================================================================
# RunSecure — runner.yml Schema Validator
# ============================================================================
# Validates a runner.yml file against the RunSecure schema (spec §3).
# Exits 0 if valid (with optional warnings to stderr), exits 1 with a
# descriptive error message if invalid.
#
# Usage:
#   bash validate-schema.sh /path/to/runner.yml
#
# Requires: yq (v4+)
# Compatible with bash 3.2+ (macOS system bash).
# ============================================================================

set -euo pipefail

command -v yq >/dev/null 2>&1 || { echo "ERROR: yq not found in PATH; install yq v4+ (https://github.com/mikefarah/yq)" >&2; exit 1; }

RUNNER_YML="${1:?Usage: validate-schema.sh /path/to/runner.yml}"

if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[validate-schema] ERROR: File not found: $RUNNER_YML" >&2
    exit 1
fi

_err()  { echo "[validate-schema] ERROR: $*" >&2; exit 1; }
_warn() { echo "[validate-schema] WARNING: $*" >&2; }

# Fail-closed yq wrapper: invokes yq and exits 1 if it fails.
# Each call passes a yq expression as $1 and the file path as $2.
# Stderr is captured so we can include yq's actual error in our message.
_yq() {
    local expr="$1"
    local file="$2"
    local out
    local err_file
    err_file=$(mktemp /tmp/runsecure-yq-err-XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -f '${err_file}'" RETURN

    if ! out=$(yq "$expr" "$file" 2>"$err_file"); then
        _err "yq failed parsing $file (expression: $expr): $(cat "$err_file")"
    fi
    printf '%s\n' "$out"
}

# ============================================================================
# 1. Known top-level keys (spec §3)
# ============================================================================
while IFS= read -r key; do
    [[ -z "$key" || "$key" == "null" ]] && continue
    case "$key" in
        version|runtime|tools|apt|http_egress|tcp_egress|dns|hardening|labels|resources|jobs)
            # Known key — ok
            ;;
        *)
            _err "runner.yml contains unknown field \"${key}\" — your RunSecure version may be older than this config requires"
            ;;
    esac
done < <(_yq 'keys | .[]' "$RUNNER_YML")

# ============================================================================
# 2. runtime: required and must match known variants
# ============================================================================
runtime=$(_yq '.runtime // ""' "$RUNNER_YML")

if [[ -z "$runtime" || "$runtime" == "null" ]]; then
    _err "runtime is required but missing from runner.yml"
fi

if ! echo "$runtime" | grep -qE '^(node:[0-9]+|python:[0-9]+\.[0-9]+|rust:(stable|beta|nightly|[0-9]+\.[0-9]+(\.[0-9]+)?))$'; then
    _err "runtime '$runtime' is invalid — must be one of: node:24, node:22, python:3.12, python:3.11, rust:stable, rust:beta, rust:nightly"
fi

# ============================================================================
# 3. http_egress: valid domain patterns only
# ============================================================================
while IFS= read -r domain; do
    [[ "$domain" == "null" || -z "$domain" ]] && continue
    if ! echo "$domain" | grep -qE '^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'; then
        _err "http_egress entry '$domain' is invalid — must be a domain like '.npmjs.org' or 'api.example.com'"
    fi
    if echo "$domain" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        _err "http_egress entry '$domain' is invalid — IP addresses are not allowed; use domain names"
    fi
done < <(_yq '.http_egress // [] | .[]' "$RUNNER_YML")

# ============================================================================
# 4. tcp_egress: must be host:port, port in [1,65535], no duplicate ports
# ============================================================================
_seen_ports_file=$(mktemp /tmp/runsecure-ports-XXXXXX)
trap 'rm -f "$_seen_ports_file"' EXIT

while IFS= read -r entry; do
    [[ "$entry" == "null" || -z "$entry" ]] && continue

    if ! echo "$entry" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?:[0-9]+$'; then
        _err "tcp_egress: invalid entry \"${entry}\" — expected host:port where host contains only alphanumeric, dot, and hyphen characters"
    fi

    port="${entry##*:}"
    host="${entry%:*}"

    # H8: reject IPv4 literals in tcp_egress host. Domain names only — IPs
    # bypass DNS-based egress filtering and let workloads address arbitrary
    # network targets directly. (IPv6 is rejected by the host-shape regex
    # above, which forbids colons in the host portion.)
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        _err "tcp_egress entry '$entry' is invalid — IP literals are not allowed; use a hostname (DNS resolution and SSRF guards apply only to names)"
    fi

    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        _err "tcp_egress: port ${port} in \"${entry}\" out of range (1-65535)"
    fi

    if [[ "$port" -eq 80 || "$port" -eq 443 ]]; then
        _err "tcp_egress entry '$entry' uses port $port — ports 80 and 443 are reserved for HTTP/HTTPS; use http_egress instead"
    fi

    if [[ -z "$host" ]]; then
        _err "tcp_egress entry '$entry' has an empty hostname"
    fi

    # Duplicate port check
    if grep -qE "^${port}:" "$_seen_ports_file" 2>/dev/null; then
        existing_entry=$(grep -E "^${port}:" "$_seen_ports_file" | head -1 | cut -d: -f2-)
        _err "tcp_egress: port ${port} declared by both \"${existing_entry}\" and \"${entry}\" — each port must be unique"
    fi
    printf '%s:%s\n' "$port" "$entry" >> "$_seen_ports_file"

done < <(_yq '.tcp_egress // [] | .[]' "$RUNNER_YML")

# ============================================================================
# 5. dns: optional block validation
# ============================================================================
dns_exists=$(_yq 'has("dns")' "$RUNNER_YML")

if [[ "$dns_exists" == "true" ]]; then
    dns_host=$(_yq '.dns.host' "$RUNNER_YML")

    if [[ "$dns_host" == "false" ]]; then
        # When host:false, either servers or hosts_file must be present
        server_count=$(_yq '.dns.servers // [] | length' "$RUNNER_YML")
        hosts_file=$(_yq '.dns.hosts_file // ""' "$RUNNER_YML")

        if [[ "$server_count" -eq 0 && ( -z "$hosts_file" || "$hosts_file" == "null" ) ]]; then
            _err "dns.host: false requires at least dns.servers or dns.hosts_file"
        fi

        # Validate server entries are IP addresses
        while IFS= read -r srv; do
            [[ "$srv" == "null" || -z "$srv" ]] && continue
            if ! echo "$srv" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^\[?[0-9a-fA-F:]+\]?$'; then
                _err "dns.servers entry '$srv' is invalid — must be an IP address"
            fi
            # Warn on RFC1918/loopback/link-local/CGNAT servers when no hosts_file
            if [[ -z "$hosts_file" || "$hosts_file" == "null" ]]; then
                local_ip=false
                if echo "$srv" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'; then
                    local_ip=true
                fi
                if [[ "$local_ip" == "true" ]]; then
                    _warn "dns.servers: ${srv} is in RFC1918/loopback/link-local/CGNAT range; verify this is intended (paired with hosts_file would suppress this)"
                fi
            fi
        done < <(_yq '.dns.servers // [] | .[]' "$RUNNER_YML")

    elif [[ "$dns_host" == "true" || "$dns_host" == "null" ]]; then
        # dns.host: true (or absent) — extra DNS fields are silently ignored
        # Warn if user specified dns.servers / hosts_file / whitelist_file / log_queries
        _extra_dns_count=0
        for _dns_field in servers hosts_file whitelist_file log_queries; do
            _val=$(_yq ".dns.${_dns_field}" "$RUNNER_YML")
            if [[ "$_val" != "null" && -n "$_val" ]]; then
                _extra_dns_count=$(( _extra_dns_count + 1 ))
            fi
        done
        if [[ "$_extra_dns_count" -gt 0 ]]; then
            _warn "dns.host: true (default) — dns.servers/hosts_file/whitelist_file/log_queries are ignored"
        fi
    else
        _err "dns.host must be 'true' or 'false', got: '$dns_host'"
    fi

    # Validate log_queries is boolean if present
    log_q=$(_yq '.dns.log_queries' "$RUNNER_YML")
    if [[ "$log_q" != "null" && "$log_q" != "true" && "$log_q" != "false" ]]; then
        _err "dns.log_queries must be true or false, got: '$log_q'"
    fi
fi

echo "[validate-schema] OK: $RUNNER_YML"
exit 0
