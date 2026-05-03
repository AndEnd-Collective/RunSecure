#!/bin/bash
# N03: cloud metadata endpoints are blocked — both by IP and by hostname
# This is the SSRF-in-CI nightmare scenario; must be airtight.
source "$(dirname "$0")/../in-container/lib.sh"

# AWS / OpenStack metadata IP
expect_fail N03 "169.254.169.254 (AWS metadata IP) blocked" -- \
    curl --max-time 5 --silent --fail --output /dev/null \
    'http://169.254.169.254/latest/meta-data/'

# GCP metadata hostname
expect_fail N03 "metadata.google.internal blocked" -- \
    curl --max-time 5 --silent --fail --output /dev/null \
    'http://metadata.google.internal/computeMetadata/v1/'

# Direct IPv4 link-local range
expect_fail N03 "any 169.254.x.x address blocked" -- \
    curl --max-time 5 --silent --fail --output /dev/null \
    'http://169.254.0.1/'

# Loopback: should be unreachable from runner network
expect_fail N03 "127.0.0.1 unreachable (no loopback HTTP service)" -- \
    curl --max-time 5 --silent --fail --output /dev/null 'http://127.0.0.1/'

summary
