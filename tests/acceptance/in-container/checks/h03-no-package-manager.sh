#!/bin/bash
# H03: package manager removed (apt/dpkg/aptitude)
# A compromised job must not be able to install attack tools at runtime.
source "$(dirname "$0")/../lib.sh"

for bin in apt apt-get apt-cache dpkg dpkg-query aptitude; do
    if command -v "$bin" >/dev/null 2>&1; then
        fail H03 "package manager '$bin' still present at $(command -v "$bin")"
    else
        pass H03 "$bin removed"
    fi
done

# Verify the apt/dpkg state directories are also gone
for dir in /var/lib/apt /var/lib/dpkg /var/cache/apt /etc/apt; do
    if [ -d "$dir" ]; then
        fail H03 "apt/dpkg state dir still present: $dir"
    else
        pass H03 "$dir removed"
    fi
done

summary
