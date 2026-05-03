#!/bin/bash
# R04: seccomp profile blocks dangerous syscalls
# We test a few high-impact ones: keyctl, swapon, perf_event_open,
# add_key, request_key. These are explicitly blocked in node-runner.json.
source "$(dirname "$0")/../lib.sh"

if ! command -v python3 >/dev/null 2>&1; then
    skip R04 "seccomp tests" "python3 not available in this image"
    summary
    exit
fi

# keyctl(2)
expect_fail R04 "keyctl blocked by seccomp" -- \
    python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
# KEYCTL_GET_KEYRING_ID = 0
ret = libc.syscall(250, 0, 0)  # x86_64 syscall number for keyctl
exit(0 if ret >= 0 else 1)
"

# perf_event_open — used by perf, can read kernel memory
expect_fail R04 "perf_event_open blocked by seccomp" -- \
    python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
ret = libc.syscall(298, 0, 0, -1, -1, 0)  # perf_event_open
exit(0 if ret >= 0 else 1)
"

# swapon — disk-write capability
expect_fail R04 "swapon blocked" -- \
    python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
ret = libc.syscall(167, b'/dev/null', 0)  # swapon
exit(0 if ret >= 0 else 1)
"

summary
