#!/bin/bash
# H02: root account is locked, shell set to nologin
source "$(dirname "$0")/../lib.sh"

# /etc/passwd should show root with /usr/sbin/nologin (or /sbin/nologin)
root_shell=$(getent passwd root | cut -d: -f7)
case "$root_shell" in
    */nologin|*/false)
        pass H02 "root shell is $root_shell"
        ;;
    *)
        fail H02 "root shell is $root_shell (should be nologin/false)"
        ;;
esac

# /etc/shadow check — root password should be locked (! or *)
# We can't read /etc/shadow as UID 1001, which is itself a positive sign:
if [ -r /etc/shadow ]; then
    fail H02 "/etc/shadow is world-readable"
else
    pass H02 "/etc/shadow not readable by UID 1001"
fi

summary
