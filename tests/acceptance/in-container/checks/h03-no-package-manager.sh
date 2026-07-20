#!/bin/bash
# H03: package-manager functionality removed; scanner inventory retained
# A compromised job must not be able to install attack tools at runtime.
source "$(dirname "$0")/../lib.sh"

for bin in apt apt-get apt-cache dpkg dpkg-query aptitude; do
    if command -v "$bin" >/dev/null 2>&1; then
        fail H03 "package manager '$bin' still present at $(command -v "$bin")"
    else
        pass H03 "$bin removed"
    fi
done

# Verify mutable apt state is gone.
for dir in /var/lib/apt /var/cache/apt /etc/apt; do
    if [ -d "$dir" ]; then
        fail H03 "apt/dpkg state dir still present: $dir"
    else
        pass H03 "$dir removed"
    fi
done

# /var/lib/dpkg/status is inert inventory used by Syft/Grype. Nothing else
# from dpkg's mutable database may survive except optional regular status.d
# fragments, and every retained path must be read-only.
if [ ! -f /var/lib/dpkg/status ] || [ -L /var/lib/dpkg/status ]; then
    fail H03 "read-only dpkg scanner inventory missing or unsafe"
elif [ "$(stat -c '%a' /var/lib/dpkg/status)" != "444" ]; then
    fail H03 "dpkg scanner inventory is not mode 444"
else
    pass H03 "read-only dpkg status inventory retained for scanners"
fi

if [ "$(stat -c '%a' /var/lib/dpkg 2>/dev/null)" != "555" ]; then
    fail H03 "dpkg scanner inventory directory is not mode 555"
else
    pass H03 "dpkg scanner inventory directory is read-only"
fi

unexpected=$(find /var/lib/dpkg -mindepth 1 \
    ! -path /var/lib/dpkg/status \
    ! -path /var/lib/dpkg/status.d \
    ! -path '/var/lib/dpkg/status.d/*' -print -quit 2>/dev/null)
if [ -n "$unexpected" ]; then
    fail H03 "mutable dpkg state survived: $unexpected"
else
    pass H03 "no mutable dpkg state retained"
fi

if [ -e /var/lib/dpkg/status.d ]; then
    invalid=$(find /var/lib/dpkg/status.d -mindepth 1 -maxdepth 1 \
        \( ! -type f -o -perm /333 \) -print -quit 2>/dev/null)
    if [ -L /var/lib/dpkg/status.d ] \
        || [ "$(stat -c '%a' /var/lib/dpkg/status.d)" != "555" ] \
        || [ -n "$invalid" ]; then
        fail H03 "dpkg status.d contains unsafe or writable state"
    else
        pass H03 "optional dpkg status.d inventory is read-only data"
    fi
fi

summary
