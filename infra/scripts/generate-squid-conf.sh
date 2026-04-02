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
    echo "  + $domain"
    PROJECT_ACL="${PROJECT_ACL}acl project_egress dstdomain ${domain}\n"
done <<< "$EGRESS_DOMAINS"

PROJECT_ACCESS="http_access allow CONNECT SSL_ports project_egress\nhttp_access allow project_egress"

# Insert project domains into the config
sed \
    -e "/# RUNSECURE_PROJECT_EGRESS_START/,/# RUNSECURE_PROJECT_EGRESS_END/c\\
# RUNSECURE_PROJECT_EGRESS_START\\
$(echo -e "$PROJECT_ACL")# RUNSECURE_PROJECT_EGRESS_END" \
    -e "/# --- DENY everything else ---/i\\
$(echo -e "$PROJECT_ACCESS")" \
    "$BASE_CONF" > "$RUNTIME_CONF"

echo "[RunSecure] Generated: $RUNTIME_CONF"
