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
#   PROXY_MAX_OPEN_FILES — ceiling for the open-file limit (default: 65536)
# ============================================================================

set -euo pipefail

SQUID_CFG="${SQUID_CFG:-/etc/squid/squid.conf}"
HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
DNSMASQ_CFG="${DNSMASQ_CFG:-/etc/dnsmasq.conf}"
ENABLE_HAPROXY="${ENABLE_HAPROXY:-false}"
ENABLE_DNSMASQ="${ENABLE_DNSMASQ:-false}"

log() { echo "[proxy-entrypoint] $*"; }

# --- Cap the open-file limit before anything starts --------------------------
# Squid and HAProxy size internal tables from the open-file limit they
# inherit, so their idle memory is proportional to it, not to traffic. The
# limit is whatever the container runtime hands out:
#
#   containerd under kind      1073741816   proxy is OOM-killed at 256Mi
#   Docker default                1048576   ~150 MiB idle
#   65536                                   ~17 MiB idle
#
# A per-job proxy serves one runner; 65536 descriptors is far more than it
# can use. Lowering a limit needs no privilege, so this works with every
# capability dropped. The limit is only ever lowered, never raised.
PROXY_MAX_OPEN_FILES="${PROXY_MAX_OPEN_FILES:-65536}"
if [[ ! "${PROXY_MAX_OPEN_FILES}" =~ ^[1-9][0-9]*$ ]]; then
    log "ERROR: PROXY_MAX_OPEN_FILES must be a positive integer, got '${PROXY_MAX_OPEN_FILES}'"
    exit 1
fi
current_open_files="$(ulimit -n)"
if [[ "${current_open_files}" == "unlimited" ]] || (( current_open_files > PROXY_MAX_OPEN_FILES )); then
    if ! ulimit -n "${PROXY_MAX_OPEN_FILES}"; then
        log "ERROR: could not lower the open-file limit from ${current_open_files} to ${PROXY_MAX_OPEN_FILES}"
        exit 1
    fi
    log "open-file limit lowered from ${current_open_files} to ${PROXY_MAX_OPEN_FILES}"
else
    log "open-file limit is ${current_open_files}"
fi

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
