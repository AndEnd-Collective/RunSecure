#!/bin/bash
# H06: /etc is locked down (chmod 555 on /etc, 444 on /etc/passwd, /etc/group)
source "$(dirname "$0")/../lib.sh"

# Cross-platform stat — GNU only on Linux containers
mode_etc=$(stat -c '%a' /etc)
mode_passwd=$(stat -c '%a' /etc/passwd)
mode_group=$(stat -c '%a' /etc/group)

[ "$mode_etc" = "555" ]    && pass H06 "/etc mode=555"     || fail H06 "/etc mode=$mode_etc (expected 555)"
[ "$mode_passwd" = "444" ] && pass H06 "/etc/passwd=444"   || fail H06 "/etc/passwd mode=$mode_passwd (expected 444)"
[ "$mode_group" = "444" ]  && pass H06 "/etc/group=444"    || fail H06 "/etc/group mode=$mode_group (expected 444)"

# Try to write to /etc — should fail
expect_fail H06 "cannot create files in /etc" -- touch /etc/runsecure-acceptance-test

# Try to modify /etc/passwd — should fail
expect_fail H06 "cannot modify /etc/passwd" -- bash -c 'echo "evil:x:1002:0::/:/bin/bash" >> /etc/passwd'

summary
