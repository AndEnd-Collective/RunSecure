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

FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3

# ---- OCI labels (static — dynamic ones added by publish-images.yml) --------
LABEL org.opencontainers.image.title="RunSecure Egress Proxy"
LABEL org.opencontainers.image.description="Multi-protocol egress filter (Squid HTTP/HTTPS + HAProxy TCP + dnsmasq DNS) used by RunSecure runner containers to enforce a per-project allowlist."
LABEL org.opencontainers.image.source="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.documentation="https://github.com/AndEnd-Collective/RunSecure#consuming-runsecure-images"
LABEL org.opencontainers.image.url="https://github.com/AndEnd-Collective/RunSecure"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="AndEnd Collective"

# `apt-get upgrade` pulls latest security patches for the base layer. Without
# this, grype flags HIGH CVEs in unpatched debian:bookworm-slim packages
# (libc6, libsystemd0, libcap2, etc) even on a fresh digest, because Debian
# ships security updates faster than the base image is rebuilt.
RUN apt-get update \
    && apt-get upgrade -y \
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
