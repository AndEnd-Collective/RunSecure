# ============================================================================
# RunSecure — Squid Egress Proxy Image
# ============================================================================
# Minimal Squid proxy for egress filtering. Runs as non-root.
# ============================================================================

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends squid \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/squid /var/spool/squid /var/run/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid /var/run/squid

COPY base.conf /etc/squid/squid.conf

EXPOSE 3128

# Run as the proxy user
USER proxy

CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
