#!/bin/bash
# ============================================================================
# RunSecure — Proxy Entrypoint (Squid + HAProxy + dnsmasq supervisor)
# ============================================================================
# Starts all enabled proxy daemons and monitors them with wait -n so that
# any single crash triggers an immediate container exit (fail-closed).
#
# Environment variables (all optional):
#   HAPROXY_CFG   — path to haproxy config (default: /etc/haproxy/haproxy.cfg)
#   DNSMASQ_CFG   — path to dnsmasq config (default: /etc/dnsmasq.conf)
#   SQUID_CFG     — path to squid config   (default: /etc/squid/squid.conf)
#   ENABLE_HAPROXY— "true" to start HAProxy (default: "false")
#   ENABLE_DNSMASQ— "true" to start dnsmasq (default: "false")
# ============================================================================

set -euo pipefail

SQUID_CFG="${SQUID_CFG:-/etc/squid/squid.conf}"
HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
DNSMASQ_CFG="${DNSMASQ_CFG:-/etc/dnsmasq.conf}"
ENABLE_HAPROXY="${ENABLE_HAPROXY:-false}"
ENABLE_DNSMASQ="${ENABLE_DNSMASQ:-false}"

log() { echo "[proxy-entrypoint] $*"; }

PIDS=()

# --- Start dnsmasq (if enabled) ---------------------------------------------
if [[ "${ENABLE_DNSMASQ}" == "true" ]]; then
    if [[ ! -f "${DNSMASQ_CFG}" ]]; then
        log "ERROR: dnsmasq config not found: ${DNSMASQ_CFG}"
        exit 1
    fi
    log "starting dnsmasq..."
    # HAProxy resolves through dnsmasq via an explicit resolvers section in
    # haproxy.cfg (127.0.0.1:53), so no /etc/resolv.conf rewrite is needed.
    # Squid resolves through its own dns_nameservers directive in squid.conf.
    dnsmasq -k --conf-file="${DNSMASQ_CFG}" &
    PIDS+=($!)
    log "dnsmasq started (PID ${PIDS[-1]})"
fi

# --- Start HAProxy (if enabled) — foreground worker mode so we can wait on it
if [[ "${ENABLE_HAPROXY}" == "true" ]]; then
    if [[ ! -f "${HAPROXY_CFG}" ]]; then
        log "ERROR: HAProxy config not found: ${HAPROXY_CFG}"
        exit 1
    fi
    log "starting haproxy..."
    # -W  worker mode (master/worker; reaps workers automatically)
    # -db debug-no-fork (keeps the master in the foreground)
    haproxy -W -db -f "${HAPROXY_CFG}" &
    PIDS+=($!)
    log "haproxy started (PID ${PIDS[-1]})"
fi

# --- Start Squid (foreground) -----------------------------------------------
log "starting squid..."
squid -N -f "${SQUID_CFG}" &
PIDS+=($!)
log "squid started (PID ${PIDS[-1]})"

log "all enabled processes started; PIDs: ${PIDS[*]}"

# --- wait -n: return as soon as ANY supervised process dies ------------------
# This is the fail-closed guarantee: one crash brings the whole container down
# rather than silently degrading (e.g., HAProxy crash leaving squid running).
wait -n "${PIDS[@]}"
RC=$?
log "one supervised process exited with code ${RC}; tearing down"
exit "${RC}"
