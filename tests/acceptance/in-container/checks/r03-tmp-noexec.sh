#!/bin/bash
# R03: /tmp is mounted noexec — downloaded binaries can't run
source "$(dirname "$0")/../lib.sh"

# Inspect the mount itself
mount_info=$(awk '$2 == "/tmp"' /proc/mounts || true)
if echo "$mount_info" | grep -q noexec; then
    pass R03 "/tmp mount has noexec flag"
else
    fail R03 "/tmp mount does not have noexec: $mount_info"
fi
if echo "$mount_info" | grep -q nosuid; then
    pass R03 "/tmp mount has nosuid flag"
else
    fail R03 "/tmp mount does not have nosuid: $mount_info"
fi

# Functional test: write a script to /tmp and try to exec it
script="/tmp/runsecure-exec-test-$$"
echo '#!/bin/sh' > "$script"
echo 'echo executed' >> "$script"
chmod +x "$script"
expect_fail R03 "cannot exec from /tmp despite +x bit" -- "$script"
rm -f "$script"

summary
