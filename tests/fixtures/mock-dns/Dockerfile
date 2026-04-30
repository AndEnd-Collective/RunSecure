# ============================================================================
# RunSecure — Mock DNS Server (test fixture)
# ============================================================================
# Runs dnsmasq as a mock DNS server for integration tests.
# Responds to queries with test-fixture entries from hosts.txt.
# ============================================================================

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsmasq \
    && rm -rf /var/lib/apt/lists/*

COPY hosts.txt /etc/mock-dns-hosts.txt
COPY dnsmasq.conf /etc/dnsmasq-test.conf

EXPOSE 53/udp
EXPOSE 53/tcp

CMD ["dnsmasq", "--no-daemon", "--conf-file=/etc/dnsmasq-test.conf"]
