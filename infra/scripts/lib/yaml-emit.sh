#!/bin/bash
# ============================================================================
# RunSecure — YAML Emitter (yq-based)
# ============================================================================
# Helper functions for building runtime-compose.yml and egress configuration
# YAML fragments. Each function emits a self-contained YAML snippet to stdout.
#
# Sourced by generate-egress-conf.sh. Not executed directly.
# ============================================================================

# Note: this file is sourced. Do NOT use `set -euo pipefail` here because
# that would override the caller's shell options. Functions handle their own
# errors.

# ----------------------------------------------------------------------------
# yaml_emit_runtime_compose_header
# Emits the comment header for runtime-compose.yml.
# ----------------------------------------------------------------------------
yaml_emit_runtime_compose_header() {
    cat <<'YAML'
# Generated at runtime by infra/scripts/generate-egress-conf.sh.
# DO NOT edit by hand — rewritten on every orchestrator run.
YAML
}

# ----------------------------------------------------------------------------
# yaml_emit_diag_volume <repo_root>
# Emits the runner _diag/ volume mount YAML fragment.
# ----------------------------------------------------------------------------
yaml_emit_diag_volume() {
    local repo_root="$1"
    cat <<YAML
services:
  runner:
    volumes:
      - ${repo_root}/_diag:/home/runner/actions-runner/_diag
YAML
}

# ----------------------------------------------------------------------------
# yaml_emit_diag_proxy_volume <repo_root>
# Emits the proxy _diag-proxy/ volume mount YAML fragment.
# ----------------------------------------------------------------------------
yaml_emit_diag_proxy_volume() {
    local repo_root="$1"
    cat <<YAML
  proxy:
    volumes:
      - ${repo_root}/_diag-proxy:/var/log/squid
YAML
}

# ----------------------------------------------------------------------------
# yaml_emit_proxy_env <haproxy_cfg> <dnsmasq_cfg> <enable_haproxy> <enable_dnsmasq>
# Emits proxy environment and config path overrides.
# ----------------------------------------------------------------------------
yaml_emit_proxy_env() {
    local haproxy_cfg="$1"
    local dnsmasq_cfg="$2"
    local enable_haproxy="$3"
    local enable_dnsmasq="$4"
    cat <<YAML
  proxy:
    environment:
      - ENABLE_HAPROXY=${enable_haproxy}
      - ENABLE_DNSMASQ=${enable_dnsmasq}
      - HAPROXY_CFG=${haproxy_cfg}
      - DNSMASQ_CFG=${dnsmasq_cfg}
YAML
}

# ----------------------------------------------------------------------------
# yaml_emit_runner_dns <proxy_ip>
# Emits the runner dns: override pointing at the proxy container.
# ----------------------------------------------------------------------------
yaml_emit_runner_dns() {
    local proxy_ip="$1"
    cat <<YAML
  runner:
    dns:
      - ${proxy_ip}
YAML
}

# ----------------------------------------------------------------------------
# yaml_emit_proxy_aliases <aliases_array>
# Emits network aliases for the proxy service. Pass alias names as arguments.
# yaml_emit_proxy_aliases "alias1" "alias2" ...
# ----------------------------------------------------------------------------
yaml_emit_proxy_aliases() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    echo "  proxy:"
    echo "    networks:"
    echo "      runner-net:"
    echo "        aliases:"
    for alias in "$@"; do
        echo "          - ${alias}"
    done
}

# ----------------------------------------------------------------------------
# yaml_emit_empty_services
# Emits a no-op services block (used when retention is disabled).
# ----------------------------------------------------------------------------
yaml_emit_empty_services() {
    echo "services: {}"
}
