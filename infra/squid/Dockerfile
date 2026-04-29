# ============================================================================
# RunSecure — Egress Proxy Image (Squid + HAProxy + dnsmasq)
# ============================================================================
# Multi-protocol egress proxy:
#   - Squid  (port 3128) — HTTP/HTTPS CONNECT filtering
#   - HAProxy (port 5432+) — TCP egress per runner.yml tcp_egress entries
#   - dnsmasq (port 53 UDP/TCP) — DNS with optional hosts file + whitelist
#
# Process supervision: proxy-entrypoint.sh starts all three daemons and
# monitors them. Exits non-zero if Squid exits non-zero.
# ============================================================================

FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         squid \
         haproxy \
         dnsmasq \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/squid /var/spool/squid /var/run/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid /var/run/squid \
    && mkdir -p /etc/haproxy /var/lib/haproxy \
    && chown -R proxy:proxy /etc/haproxy /var/lib/haproxy \
    && mkdir -p /var/run/dnsmasq \
    && chown -R proxy:proxy /var/run/dnsmasq

COPY base.conf /etc/squid/squid.conf
COPY haproxy.cfg.tmpl /etc/haproxy/haproxy.cfg.tmpl
COPY dnsmasq.conf.tmpl /etc/dnsmasq.conf.tmpl
COPY proxy-entrypoint.sh /usr/local/bin/proxy-entrypoint.sh

RUN chmod +x /usr/local/bin/proxy-entrypoint.sh

# No EXPOSE — the proxy is only accessed via the internal Docker network
# by name (proxy:3128 / proxy:5432 / proxy:53). Omitting EXPOSE prevents
# accidental host port binding in compose configs.

# Run as the proxy user
USER proxy

CMD ["/usr/local/bin/proxy-entrypoint.sh"]
