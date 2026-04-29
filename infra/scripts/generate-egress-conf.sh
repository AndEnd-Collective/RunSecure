#!/bin/bash
# ============================================================================
# RunSecure — Egress Configuration Generator
# ============================================================================
# Main orchestration script that reads runner.yml and produces:
#   1. infra/squid/runtime.conf   — Squid HTTP/HTTPS egress config
#   2. infra/squid/haproxy.cfg    — HAProxy TCP egress config (if tcp_egress set)
#   3. infra/squid/dnsmasq.conf   — dnsmasq DNS config (if dns: host:false)
#   4. infra/runtime-compose.yml  — Docker Compose overlay (diag mounts, env)
#
# Replaces the old generate-squid-conf.sh + the inline overlay generation
# that was previously in run.sh.
#
# Usage:
#   ./infra/scripts/generate-egress-conf.sh /path/to/project
#
# Environment variables honored:
#   RUNSECURE_DIAG_RETENTION  — "0" skips diag bind mounts (default: 1)
#
# Requires: yq (v4+), bash 3.2+
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROJECT_DIR="${1:?Usage: generate-egress-conf.sh /path/to/project}"
RUNNER_YML="${PROJECT_DIR}/.github/runner.yml"

BASE_CONF="${RUNSECURE_ROOT}/infra/squid/base.conf"
RUNTIME_CONF="${RUNSECURE_ROOT}/infra/squid/runtime.conf"
HAPROXY_CFG="${RUNSECURE_ROOT}/infra/squid/haproxy.cfg"
DNSMASQ_CONF="${RUNSECURE_ROOT}/infra/squid/dnsmasq.conf"
RUNTIME_COMPOSE="${RUNSECURE_ROOT}/infra/runtime-compose.yml"

HAPROXY_TMPL="${RUNSECURE_ROOT}/infra/squid/haproxy.cfg.tmpl"
DNSMASQ_TMPL="${RUNSECURE_ROOT}/infra/squid/dnsmasq.conf.tmpl"

# Proxy static IP (matches IPAM assignment in docker-compose.yml)
PROXY_IP="10.11.12.13"

# Load YAML emitter helpers
# SC1091: path is computed; shellcheck cannot follow it statically
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/yaml-emit.sh"

_log() { echo "[generate-egress-conf] $*" >&2; }
_err() { echo "[generate-egress-conf] ERROR: $*" >&2; exit 1; }

# ============================================================================
# Validate schema first
# ============================================================================
if [[ -f "$RUNNER_YML" ]]; then
    bash "${SCRIPT_DIR}/lib/validate-schema.sh" "$RUNNER_YML"
fi

# ============================================================================
# 1. Squid HTTP/HTTPS config (runtime.conf)
# ============================================================================
_generate_squid_conf() {
    if [[ ! -f "$RUNNER_YML" ]]; then
        _log "No runner.yml — using base squid config."
        cp "$BASE_CONF" "$RUNTIME_CONF"
        return
    fi

    # Collect domains from http_egress
    EGRESS_DOMAINS=$(yq '(.http_egress // []) | .[]' "$RUNNER_YML" 2>/dev/null || true)

    if [[ -z "$EGRESS_DOMAINS" ]]; then
        _log "No project-specific HTTP egress — using base squid config."
        cp "$BASE_CONF" "$RUNTIME_CONF"
        return
    fi

    _log "Adding project HTTP egress domains:"

    PROJECT_ACL=""
    while IFS= read -r domain; do
        domain=$(echo "$domain" | tr -d '[:space:]')
        [[ -z "$domain" || "$domain" == "null" ]] && continue
        if [[ ! "$domain" =~ ^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
            _log "WARNING: Skipping invalid domain: $domain"
            continue
        fi
        _log "  + $domain"
        PROJECT_ACL="${PROJECT_ACL}acl project_egress dstdomain ${domain}\n"
    done <<< "$EGRESS_DOMAINS"

    PROJECT_ACCESS="http_access allow CONNECT SSL_ports project_egress\nhttp_access allow project_egress"

    RS_PROJECT_ACL=$(printf '%b' "$PROJECT_ACL") \
    RS_PROJECT_ACCESS=$(printf '%b' "$PROJECT_ACCESS") \
    awk '
        in_egress_block {
            if (/# RUNSECURE_PROJECT_EGRESS_END/) {
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

    _log "Generated: $RUNTIME_CONF"
}

# ============================================================================
# 2. HAProxy TCP egress config
# ============================================================================
_generate_haproxy_cfg() {
    if [[ ! -f "$RUNNER_YML" ]]; then
        echo "false"
        return
    fi

    # Check if tcp_egress has any entries
    tcp_count=$(yq '.tcp_egress // [] | length' "$RUNNER_YML" 2>/dev/null || echo "0")

    if [[ "$tcp_count" -eq 0 ]]; then
        echo "false"
        return
    fi

    _log "Building HAProxy config for TCP egress:"

    ENTRIES_BLOCK=""
    while IFS= read -r entry; do
        [[ "$entry" == "null" || -z "$entry" ]] && continue
        host="${entry%:*}"
        port="${entry##*:}"
        _log "  TCP: $host:$port (HAProxy frontend listening on :$port)"

        ENTRIES_BLOCK="${ENTRIES_BLOCK}
frontend tcp_${port}
    bind 0.0.0.0:${port}
    default_backend backend_${port}

backend backend_${port}
    server srv_${port} ${host}:${port} check inter 10s
"
    done < <(yq '.tcp_egress // [] | .[]' "$RUNNER_YML" 2>/dev/null || true)

    if [[ -z "$ENTRIES_BLOCK" ]]; then
        echo "false"
        return
    fi

    # Determine whether dnsmasq will be active (so we can add a resolvers
    # section pointing haproxy at 127.0.0.1:53, avoiding any need to write
    # /etc/resolv.conf from a non-root container process).
    local dns_host_raw
    dns_host_raw=$(yq '.dns.host' "$RUNNER_YML" 2>/dev/null || echo "null")
    local resolvers_block=""
    if [[ "$dns_host_raw" == "false" ]]; then
        resolvers_block="resolvers dnsmasq_local\n    nameserver local 127.0.0.1:53\n    resolve_retries 3\n    timeout retry 1s\n    hold valid 10s\n    accepted_payload_size 8192"
    fi

    # Build config from template using awk.
    # Pass multi-line content via ENVIRON to avoid awk -v newline limitations.
    RS_HAPROXY_ENTRIES=$(printf '%b' "$ENTRIES_BLOCK") \
    RS_HAPROXY_RESOLVERS=$(printf '%b' "$resolvers_block") \
    awk '
        /# HAPROXY_RESOLVERS_PLACEHOLDER/ {
            if (ENVIRON["RS_HAPROXY_RESOLVERS"] != "") print ENVIRON["RS_HAPROXY_RESOLVERS"]
            next
        }
        /# HAPROXY_ENTRIES_START/ { print; print ENVIRON["RS_HAPROXY_ENTRIES"]; found=1; next }
        found && /# HAPROXY_ENTRIES_END/ { found=0 }
        !found { print }
    ' "$HAPROXY_TMPL" > "$HAPROXY_CFG"

    _log "Generated: $HAPROXY_CFG"
    echo "true"
}

# ============================================================================
# 3. dnsmasq config
# ============================================================================
_generate_dnsmasq_conf() {
    if [[ ! -f "$RUNNER_YML" ]]; then
        echo "false"
        return
    fi

    # Read dns.host directly — yq v4 prints boolean false as the string "false"
    dns_host=$(yq '.dns.host' "$RUNNER_YML" 2>/dev/null || echo "null")

    # If dns is absent or dns.host:true/null, use host DNS (no dnsmasq needed)
    if [[ "$dns_host" != "false" ]]; then
        echo "false"
        return
    fi

    _log "Building dnsmasq config (dns.host: false)..."

    # log_queries — yq v4 prints boolean false directly as "false"; absent is "null"
    log_q_raw=$(yq '.dns.log_queries' "$RUNNER_YML" 2>/dev/null || echo "null")
    # Default: true when not set
    log_q="$([[ "$log_q_raw" == "false" ]] && echo "false" || echo "true")"

    # Build the dnsmasq config by processing the template line by line,
    # substituting placeholder comments with actual configuration.
    true > "$DNSMASQ_CONF"
    while IFS= read -r line; do
        case "$line" in
            "# LOG_QUERIES_PLACEHOLDER")
                if [[ "$log_q" == "true" ]]; then
                    echo "log-queries"
                else
                    echo "# log-queries disabled"
                fi
                ;;
            "# SERVER_ENTRIES_PLACEHOLDER")
                while IFS= read -r srv; do
                    [[ "$srv" == "null" || -z "$srv" ]] && continue
                    echo "server=${srv}"
                    _log "  DNS server: $srv"
                done < <(yq '.dns.servers // [] | .[]' "$RUNNER_YML" 2>/dev/null || true)
                ;;
            "# HOSTS_FILE_PLACEHOLDER")
                hosts_file=$(yq '.dns.hosts_file // ""' "$RUNNER_YML" 2>/dev/null || echo "")
                if [[ -n "$hosts_file" && "$hosts_file" != "null" ]]; then
                    fetched_hosts=$(mktemp /tmp/runsecure-hosts-XXXXXX)
                    if bash "${SCRIPT_DIR}/lib/fetch-runtime-file.sh" "$hosts_file" "$fetched_hosts"; then
                        echo "addn-hosts=${fetched_hosts}"
                        _log "  Hosts file: $hosts_file -> $fetched_hosts"
                    else
                        _err "Failed to fetch dns.hosts_file: $hosts_file"
                    fi
                else
                    echo "# No hosts file configured"
                fi
                ;;
            "# WHITELIST_PLACEHOLDER")
                whitelist_file=$(yq '.dns.whitelist_file // ""' "$RUNNER_YML" 2>/dev/null || echo "")
                if [[ -n "$whitelist_file" && "$whitelist_file" != "null" ]]; then
                    fetched_whitelist=$(mktemp /tmp/runsecure-whitelist-XXXXXX)
                    if bash "${SCRIPT_DIR}/lib/fetch-runtime-file.sh" "$whitelist_file" "$fetched_whitelist"; then
                        _log "  Whitelist file: $whitelist_file -> $fetched_whitelist"
                        while IFS= read -r domain; do
                            domain=$(echo "$domain" | tr -d '[:space:]' | sed 's/#.*//')
                            [[ -z "$domain" ]] && continue
                            echo "server=/${domain}/"
                        done < "$fetched_whitelist"
                    else
                        _err "Failed to fetch dns.whitelist_file: $whitelist_file"
                    fi
                else
                    echo "# No whitelist configured"
                fi
                ;;
            "# DENY_OTHER_PLACEHOLDER")
                whitelist_file=$(yq '.dns.whitelist_file // ""' "$RUNNER_YML" 2>/dev/null || echo "")
                if [[ -n "$whitelist_file" && "$whitelist_file" != "null" ]]; then
                    echo "# Domains not in whitelist are refused (dnsmasq returns NXDOMAIN)"
                else
                    echo "# No whitelist — all queries forwarded to configured servers"
                fi
                ;;
            *)
                echo "$line"
                ;;
        esac
    done < "$DNSMASQ_TMPL" >> "$DNSMASQ_CONF"

    _log "Generated: $DNSMASQ_CONF"
    echo "true"
}

# ============================================================================
# 4. runtime-compose.yml overlay
# ============================================================================
_generate_runtime_compose() {
    local enable_haproxy="$1"
    local enable_dnsmasq="$2"

    {
        yaml_emit_runtime_compose_header

        if [[ "${RUNSECURE_DIAG_RETENTION:-1}" == "0" ]]; then
            _log "RUNSECURE_DIAG_RETENTION=0 — skipping diag bind mounts."
            yaml_emit_empty_services
        else
            # Build runner block content — collect volumes and dns together
            # to avoid duplicate runner: keys (YAML last-key-wins silently
            # drops the first block).
            local runner_volumes=""
            local runner_dns=""

            runner_volumes="      - ${RUNSECURE_ROOT}/_diag:/home/runner/actions-runner/_diag\n"

            if [[ "$enable_dnsmasq" == "true" ]]; then
                # When dnsmasq is active, runner should use proxy as DNS
                runner_dns="    dns:\n      - ${PROXY_IP}"
            fi

            echo "services:"

            # Emit single runner: block with all content
            echo "  runner:"
            printf "    volumes:\n"
            printf '%b' "$runner_volumes"
            if [[ -n "$runner_dns" ]]; then
                printf '%b\n' "$runner_dns"
            fi

            # Proxy block: diag volume + env flags + config volume mounts
            echo "  proxy:"
            echo "    volumes:"
            echo "      - ${RUNSECURE_ROOT}/_diag-proxy:/var/log/squid"
            if [[ "$enable_haproxy" == "true" ]]; then
                echo "      - ${HAPROXY_CFG}:/etc/haproxy/haproxy.cfg:ro"
            fi
            if [[ "$enable_dnsmasq" == "true" ]]; then
                echo "      - ${DNSMASQ_CONF}:/etc/dnsmasq.conf:ro"
            fi
            echo "    environment:"
            echo "      - ENABLE_HAPROXY=${enable_haproxy}"
            echo "      - ENABLE_DNSMASQ=${enable_dnsmasq}"
        fi
    } > "$RUNTIME_COMPOSE"

    _log "Generated: $RUNTIME_COMPOSE"
}

# ============================================================================
# Main execution
# ============================================================================
_generate_squid_conf

HAPROXY_ENABLED=$(_generate_haproxy_cfg)
DNSMASQ_ENABLED=$(_generate_dnsmasq_conf)

_generate_runtime_compose "$HAPROXY_ENABLED" "$DNSMASQ_ENABLED"

_log "Egress configuration complete."
_log "  Squid HTTP/HTTPS: $RUNTIME_CONF"
if [[ "$HAPROXY_ENABLED" == "true" ]]; then
    _log "  HAProxy TCP:      $HAPROXY_CFG"
fi
if [[ "$DNSMASQ_ENABLED" == "true" ]]; then
    _log "  dnsmasq DNS:      $DNSMASQ_CONF"
fi
_log "  Compose overlay:  $RUNTIME_COMPOSE"
