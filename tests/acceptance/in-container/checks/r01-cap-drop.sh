#!/bin/bash
# R01: cap_drop ALL — capability-using operations fail
# Tested via syscalls that require specific caps.
source "$(dirname "$0")/../lib.sh"

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

# CAP_NET_BIND_SERVICE: binding ports < 1024
# (only the proxy gets this cap; runner doesn't)
if command -v python3 >/dev/null 2>&1; then
    expect_fail R01 "cannot bind privileged port (CAP_NET_BIND_SERVICE dropped)" -- \
        python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 80))
"
fi

summary
