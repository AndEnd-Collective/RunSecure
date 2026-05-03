#!/bin/bash
# H04: network recon tools removed
# An attacker can't discover internal services without these.
source "$(dirname "$0")/../lib.sh"

for bin in nc netcat ncat ssh sshd telnet wget; do
    if command -v "$bin" >/dev/null 2>&1; then
        fail H04 "network recon tool '$bin' still present at $(command -v "$bin")"
    else
        pass H04 "$bin removed"
    fi
done

# `ping` is special — it's needed by some legitimate health-check scripts,
# but should NOT have setuid (so it can't actually open raw sockets as 1001).
if command -v ping >/dev/null 2>&1; then
    ping_path=$(command -v ping)
    if [ -u "$ping_path" ]; then
        fail H04 "ping has setuid bit at $ping_path (allows raw socket creation)"
    else
        pass H04 "ping present but no setuid (raw sockets blocked anyway)"
    fi
else
    pass H04 "ping removed"
fi

summary
