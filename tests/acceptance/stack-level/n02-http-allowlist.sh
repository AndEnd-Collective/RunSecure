#!/bin/bash
# N02: Squid allows whitelisted domains, blocks others.
source "$(dirname "$0")/../in-container/lib.sh"

# Allowed: github.com (in base allowlist)
expect_pass N02 "https://github.com (allowed) reaches origin via proxy" -- \
    curl --max-time 10 --silent --fail --output /dev/null https://github.com

# Allowed: npmjs.org (in base allowlist)
expect_pass N02 "https://registry.npmjs.org (allowed) reaches origin" -- \
    curl --max-time 10 --silent --fail --output /dev/null https://registry.npmjs.org/-/ping

# Blocked: arbitrary internet domain
expect_fail N02 "https://example.invalid.com (not on allowlist) is refused" -- \
    curl --max-time 10 --silent --fail --output /dev/null https://example.invalid.com

# Blocked: known-bad pattern (we use a domain we control / RFC-reserved)
expect_fail N02 "https://attacker.invalid (not on allowlist) is refused" -- \
    curl --max-time 10 --silent --fail --output /dev/null https://attacker.invalid

summary
