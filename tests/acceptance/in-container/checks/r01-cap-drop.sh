#!/bin/bash
# R01: cap_drop ALL — all Linux capability masks are empty and operations
# requiring capabilities fail. Inspecting the masks is the authoritative
# check: Docker commonly sets net.ipv4.ip_unprivileged_port_start=0, which
# allows an unprivileged process to bind port 80 without NET_BIND_SERVICE.
source "$(dirname "$0")/../lib.sh"

for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    value=$(awk -v key="${field}:" '$1 == key { print $2 }' /proc/self/status)
    if [[ -z "$value" ]]; then
        fail R01 "$field missing from /proc/self/status"
    elif [[ "$value" =~ ^0+$ ]]; then
        pass R01 "$field is empty (cap_drop ALL)"
    else
        fail R01 "$field=$value (expected all zeroes)"
    fi
done

# CAP_NET_RAW: opening a raw socket
# We use python because nothing else portable is left after hardening.
# If python isn't here either, try a different approach.
if command -v python3 >/dev/null 2>&1; then
    expect_fail R01 "cannot open raw socket (CAP_NET_RAW dropped)" -- \
        python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)"
else
    skip R01 "raw-socket test" "python3 not available in this image"
fi

# CAP_SYS_ADMIN: mounting filesystems
# `mount` itself is removed, but we can try the syscall directly via
# python if available.
if command -v python3 >/dev/null 2>&1; then
    expect_fail R01 "cannot mount tmpfs (CAP_SYS_ADMIN dropped)" -- \
        python3 -c "
import ctypes, ctypes.util, os
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
src = os.path.expanduser('~/.acceptance-mount-test')
os.makedirs(src, exist_ok=True)
ret = libc.mount(b'tmpfs', src.encode(), b'tmpfs', 0, b'')
exit(0 if ret == 0 else 1)
"
fi

summary
