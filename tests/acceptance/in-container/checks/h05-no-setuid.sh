#!/bin/bash
# H05: no setuid/setgid binaries on PATH
# finalize-hardening.sh strips these; no later layer should re-add.
source "$(dirname "$0")/../lib.sh"

found=$(find /usr/bin /usr/sbin /bin /sbin /usr/local/bin -xdev -perm /6000 -type f 2>/dev/null)
if [ -z "$found" ]; then
    pass H05 "no setuid/setgid binaries in PATH directories"
else
    fail H05 "setuid/setgid binaries found:"
    echo "$found" | head -5 >&2
fi

summary
