#!/bin/bash
# H01: container runs as UID 1001, not root
source "$(dirname "$0")/../lib.sh"

uid=$(id -u)
gid=$(id -g)
if [ "$uid" = "1001" ]; then
    pass H01 "process runs as UID 1001 (got $uid)"
else
    fail H01 "process should run as UID 1001, got $uid"
fi

# Group 0 (root group) is intentional — runner needs write access to its
# own home, which is owned by root:root with mode g+w. See base.Dockerfile.
if [ "$gid" = "0" ]; then
    pass H01 "primary GID 0 (intentional — runner home is g+w root:root)"
else
    fail H01 "expected primary GID 0, got $gid"
fi

summary
