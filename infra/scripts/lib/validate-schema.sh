#!/bin/bash
# ============================================================================
# RunSecure — runner.yml Schema Validator
# ============================================================================
# Validates a runner.yml file against the RunSecure schema (spec §3).
# Exits 0 if valid, exits 1 with a descriptive error message if invalid.
#
# Usage:
#   bash validate-schema.sh /path/to/runner.yml
#
# Requires: yq (v4+)
# Compatible with bash 3.2+ (macOS system bash).
# ============================================================================

set -euo pipefail

RUNNER_YML="${1:?Usage: validate-schema.sh /path/to/runner.yml}"

if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[validate-schema] ERROR: File not found: $RUNNER_YML" >&2
    exit 1
fi

_err() { echo "[validate-schema] ERROR: $*" >&2; exit 1; }

# ============================================================================
# 1. Known top-level keys (spec §3)
# ============================================================================
# Read all actual top-level keys and check each against the known list
while IFS= read -r key; do
    [[ -z "$key" || "$key" == "null" ]] && continue
    case "$key" in
        version|runtime|tools|apt|egress|http_egress|tcp_egress|dns|labels|resources|jobs)
            # Known key — ok
            ;;
        *)
            _err "unknown field '$key' — unrecognized field in runner.yml. Allowed: version runtime tools apt egress http_egress tcp_egress dns labels resources jobs"
            ;;
    esac
done < <(yq 'keys | .[]' "$RUNNER_YML" 2>/dev/null || true)

# ============================================================================
# 2. runtime: required and must match known variants
# ============================================================================
runtime=$(yq '.runtime // ""' "$RUNNER_YML" 2>/dev/null || true)

if [[ -z "$runtime" || "$runtime" == "null" ]]; then
    _err "runtime is required but missing from runner.yml"
fi

# Validate runtime format: lang:version
# Accepted: node:<N>, python:<M.N>, rust:<channel>
if ! echo "$runtime" | grep -qE '^(node:[0-9]+|python:[0-9]+\.[0-9]+|rust:(stable|beta|nightly|[0-9]+\.[0-9]+(\.[0-9]+)?))$'; then
    _err "runtime '$runtime' is invalid — must be one of: node:24, node:22, python:3.12, python:3.11, rust:stable, rust:beta, rust:nightly"
fi

# ============================================================================
# 3. http_egress / egress: valid domain patterns only
# ============================================================================
for field in http_egress egress; do
    while IFS= read -r domain; do
        [[ "$domain" == "null" || -z "$domain" ]] && continue
        # Allow optional leading dot for wildcard, then standard domain chars
        if ! echo "$domain" | grep -qE '^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'; then
            _err "http_egress entry '$domain' is invalid — must be a domain like '.npmjs.org' or 'api.example.com'"
        fi
        # Reject bare IP addresses in http_egress
        if echo "$domain" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            _err "http_egress entry '$domain' is invalid — IP addresses are not allowed; use domain names"
        fi
    done < <(yq ".${field} // [] | .[]" "$RUNNER_YML" 2>/dev/null || true)
done

# ============================================================================
# 4. tcp_egress: must be host:port, port in [1,65535], no duplicate ports
# ============================================================================
# We use a temp file to track seen ports (bash 3.2 has no associative arrays)
_seen_ports_file=$(mktemp /tmp/runsecure-ports-XXXXXX)
trap 'rm -f "$_seen_ports_file"' EXIT

while IFS= read -r entry; do
    [[ "$entry" == "null" || -z "$entry" ]] && continue

    # Must match host:port format (no colons in host)
    if ! echo "$entry" | grep -qE '^[^:]+:[0-9]+$'; then
        _err "tcp_egress entry '$entry' is invalid — must be in host:port format (e.g., ep-foo.neon.tech:5432)"
    fi

    port="${entry##*:}"
    host="${entry%:*}"

    # Port must be 1-65535
    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        _err "tcp_egress entry '$entry' has invalid port $port — must be between 1 and 65535"
    fi

    # Port 80 and 443 reserved for HTTP/HTTPS
    if [[ "$port" -eq 80 || "$port" -eq 443 ]]; then
        _err "tcp_egress entry '$entry' uses port $port — ports 80 and 443 are reserved for HTTP/HTTPS; use http_egress instead"
    fi

    # Hostname must be non-empty
    if [[ -z "$host" ]]; then
        _err "tcp_egress entry '$entry' has an empty hostname"
    fi

    # Duplicate port check (each port must be unique for HAProxy listener)
    if grep -qE "^${port}$" "$_seen_ports_file" 2>/dev/null; then
        _err "tcp_egress has duplicate port $port — each port must be unique (port collision for HAProxy frontend)"
    fi
    echo "$port" >> "$_seen_ports_file"

done < <(yq '.tcp_egress // [] | .[]' "$RUNNER_YML" 2>/dev/null || true)

# ============================================================================
# 5. dns: optional block validation
# ============================================================================
dns_exists=$(yq 'has("dns")' "$RUNNER_YML" 2>/dev/null || echo "false")

if [[ "$dns_exists" == "true" ]]; then
    # Read .dns.host directly — yq v4 prints boolean false as the string "false"
    # We cannot use // "null" because yq treats boolean false as falsy
    dns_host_raw=$(yq '.dns.host' "$RUNNER_YML" 2>/dev/null || echo "null")
    # yq outputs "null" (unquoted) when the key is absent
    dns_host="${dns_host_raw}"

    if [[ "$dns_host" == "false" ]]; then
        # When host:false, either servers or hosts_file must be present
        server_count=$(yq '.dns.servers // [] | length' "$RUNNER_YML" 2>/dev/null || echo "0")
        hosts_file=$(yq '.dns.hosts_file // ""' "$RUNNER_YML" 2>/dev/null || echo "")

        if [[ "$server_count" -eq 0 && ( -z "$hosts_file" || "$hosts_file" == "null" ) ]]; then
            _err "dns.servers is required when dns.host is false (and no dns.hosts_file is set) — specify at least one upstream DNS server"
        fi

        # Validate server entries are IP addresses
        while IFS= read -r srv; do
            [[ "$srv" == "null" || -z "$srv" ]] && continue
            if ! echo "$srv" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^\[?[0-9a-fA-F:]+\]?$'; then
                _err "dns.servers entry '$srv' is invalid — must be an IP address"
            fi
        done < <(yq '.dns.servers // [] | .[]' "$RUNNER_YML" 2>/dev/null || true)

    elif [[ "$dns_host" != "true" && "$dns_host" != "null" ]]; then
        _err "dns.host must be 'true' or 'false', got: '$dns_host'"
    fi

    # Validate log_queries is boolean if present
    # yq v4 prints boolean false directly as "false"; absent key prints "null"
    log_q=$(yq '.dns.log_queries' "$RUNNER_YML" 2>/dev/null || echo "null")
    if [[ "$log_q" != "null" && "$log_q" != "true" && "$log_q" != "false" ]]; then
        _err "dns.log_queries must be true or false, got: '$log_q'"
    fi
fi

echo "[validate-schema] OK: $RUNNER_YML"
exit 0
