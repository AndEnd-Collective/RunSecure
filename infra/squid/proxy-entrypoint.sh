#!/bin/bash
# ============================================================================
# RunSecure — Proxy Entrypoint (Squid + HAProxy + dnsmasq supervisor)
# ============================================================================
# Starts all proxy daemons and monitors them. Exits with Squid's exit code.
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

# --- Start dnsmasq (if enabled) ----------------------------------------------
if [[ "$ENABLE_DNSMASQ" == "true" ]]; then
    if [[ ! -f "$DNSMASQ_CFG" ]]; then
        log "ERROR: dnsmasq config not found: $DNSMASQ_CFG"
        exit 1
    fi
    log "Starting dnsmasq..."
    dnsmasq --no-daemon --conf-file="$DNSMASQ_CFG" &
    DNSMASQ_PID=$!
    log "dnsmasq started (PID $DNSMASQ_PID)"
else
    DNSMASQ_PID=""
fi

# --- Start HAProxy (if enabled) ---------------------------------------------
if [[ "$ENABLE_HAPROXY" == "true" ]]; then
    if [[ ! -f "$HAPROXY_CFG" ]]; then
        log "ERROR: HAProxy config not found: $HAPROXY_CFG"
        exit 1
    fi
    log "Starting HAProxy..."
    haproxy -f "$HAPROXY_CFG" -D -p /var/lib/haproxy/haproxy.pid
    log "HAProxy started"
fi

# --- Start Squid (foreground — this is PID1 ownership) ----------------------
log "Starting Squid..."
# Squid must initialize its cache dirs on first run.
squid -N -f "$SQUID_CFG" &
SQUID_PID=$!
log "Squid started (PID $SQUID_PID)"

# --- Trap signals and propagate to children ---------------------------------
_shutdown() {
    log "Received shutdown signal. Stopping services..."
    if [[ -n "$SQUID_PID" ]] && kill -0 "$SQUID_PID" 2>/dev/null; then
        squid -k shutdown -f "$SQUID_CFG" 2>/dev/null || kill -TERM "$SQUID_PID" 2>/dev/null || true
    fi
    if [[ "$ENABLE_HAPROXY" == "true" ]]; then
        if [[ -f /var/lib/haproxy/haproxy.pid ]]; then
            kill -TERM "$(cat /var/lib/haproxy/haproxy.pid)" 2>/dev/null || true
        fi
    fi
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill -TERM "$DNSMASQ_PID" 2>/dev/null || true
    fi
}
trap _shutdown TERM INT

# --- Monitor loop: exit if Squid dies ---------------------------------------
wait "$SQUID_PID"
SQUID_EXIT=$?

log "Squid exited with code $SQUID_EXIT. Shutting down other services..."

if [[ "$ENABLE_HAPROXY" == "true" ]]; then
    if [[ -f /var/lib/haproxy/haproxy.pid ]]; then
        kill -TERM "$(cat /var/lib/haproxy/haproxy.pid)" 2>/dev/null || true
    fi
fi
if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
    kill -TERM "$DNSMASQ_PID" 2>/dev/null || true
fi

exit "$SQUID_EXIT"
