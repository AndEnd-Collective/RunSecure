# ============================================================================
# RunSecure — Squid Egress Proxy Image
# ============================================================================
# Minimal Squid proxy for egress filtering. Runs as non-root.
# ============================================================================

FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a

RUN apt-get update \
    && apt-get install -y --no-install-recommends squid \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/squid /var/spool/squid /var/run/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid /var/run/squid

COPY base.conf /etc/squid/squid.conf

# No EXPOSE — the proxy is only accessed via the internal Docker network
# by name (proxy:3128). Omitting EXPOSE prevents accidental host port
# binding in compose configs that forget to set ports: [].

# Run as the proxy user
USER proxy

CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
