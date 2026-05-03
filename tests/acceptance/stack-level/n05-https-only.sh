#!/bin/bash
# N05: Squid CONNECT method enforcement — only specific ports allowed
source "$(dirname "$0")/../in-container/lib.sh"

# CONNECT to non-443 port should be refused (e.g. trying to use HTTPS proxy
# to tunnel to SSH port 22 on github.com)
# We don't actually open a connection; we just verify the proxy refuses
# the CONNECT.
expect_fail N05 "CONNECT to github.com:22 refused (only 443 in SSL_ports)" -- \
    curl --max-time 5 --silent --fail -p -x http://proxy:3128 \
    --proxytunnel github.com:22

summary
