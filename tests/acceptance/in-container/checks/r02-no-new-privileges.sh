#!/bin/bash
# R02: no-new-privileges:true — setuid binaries can't escalate
# Even if a setuid binary were re-introduced (it shouldn't be), it
# wouldn't gain privileges.
source "$(dirname "$0")/../lib.sh"

# Check the kernel-level flag via /proc
if [ -r /proc/self/status ]; then
    nnp=$(grep '^NoNewPrivs:' /proc/self/status | awk '{print $2}')
    if [ "$nnp" = "1" ]; then
        pass R02 "kernel reports NoNewPrivs=1"
    else
        fail R02 "NoNewPrivs=$nnp (should be 1)"
    fi
else
    skip R02 "NoNewPrivs check" "/proc/self/status not readable"
fi

summary
