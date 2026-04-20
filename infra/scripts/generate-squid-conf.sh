#!/bin/bash
# ============================================================================
# RunSecure — Squid Config Generator
# ============================================================================
# Merges the base squid.conf with project-specific egress domains from
# runner.yml to produce a runtime squid configuration.
#
# Usage:
#   ./infra/scripts/generate-squid-conf.sh /path/to/project
#
# Output:
#   Writes infra/squid/runtime.conf (used by docker-compose)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROJECT_DIR="${1:?Usage: generate-squid-conf.sh /path/to/project}"
RUNNER_YML="${PROJECT_DIR}/.github/runner.yml"

BASE_CONF="${RUNSECURE_ROOT}/infra/squid/base.conf"
RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"

if [[ ! -f "$RUNNER_YML" ]]; then
    echo "[RunSecure] No runner.yml — using base squid config."
    cp "$BASE_CONF" "$RUNTIME_CONF"
    exit 0
fi

# Read project-specific egress domains
EGRESS_DOMAINS=$(yq '.egress // [] | .[]' "$RUNNER_YML" 2>/dev/null || true)

if [[ -z "$EGRESS_DOMAINS" ]]; then
    echo "[RunSecure] No project-specific egress — using base squid config."
    cp "$BASE_CONF" "$RUNTIME_CONF"
    exit 0
fi

echo "[RunSecure] Adding project egress domains:"

# Build the ACL and access lines
PROJECT_ACL=""
PROJECT_ACCESS=""

while IFS= read -r domain; do
    # Sanitize: strip whitespace and reject anything that isn't a valid domain
    domain=$(echo "$domain" | tr -d '[:space:]')
    if [[ ! "$domain" =~ ^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
        echo "[RunSecure] WARNING: Skipping invalid egress domain: $domain"
        continue
    fi
    echo "  + $domain"
    PROJECT_ACL="${PROJECT_ACL}acl project_egress dstdomain ${domain}\n"
done <<< "$EGRESS_DOMAINS"

PROJECT_ACCESS="http_access allow CONNECT SSL_ports project_egress\nhttp_access allow project_egress"

# Insert project domains into the config.
# Implementation note: previously this used GNU-sed `c\` and `i\` commands
# which fail on BSD sed (default on macOS). awk is portable across both
# sed flavours, and ENVIRON[] (instead of -v) accepts multi-line values.
RS_PROJECT_ACL=$(printf '%b' "$PROJECT_ACL") \
RS_PROJECT_ACCESS=$(printf '%b' "$PROJECT_ACCESS") \
awk '
    in_egress_block {
        if (/# RUNSECURE_PROJECT_EGRESS_END/) {
            # ENVIRON value loses its trailing newline to command substitution,
            # so always emit one before the END marker.
            print "# RUNSECURE_PROJECT_EGRESS_START"
            print ENVIRON["RS_PROJECT_ACL"]
            print "# RUNSECURE_PROJECT_EGRESS_END"
            in_egress_block = 0
        }
        next
    }
    /# RUNSECURE_PROJECT_EGRESS_START/ {
        in_egress_block = 1
        next
    }
    /# --- DENY everything else ---/ {
        printf "%s\n", ENVIRON["RS_PROJECT_ACCESS"]
    }
    { print }
' "$BASE_CONF" > "$RUNTIME_CONF"

echo "[RunSecure] Generated: $RUNTIME_CONF"
