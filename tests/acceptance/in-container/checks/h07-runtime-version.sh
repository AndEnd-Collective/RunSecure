#!/bin/bash
# H07: the installed language runtime version must match what the image tag claims
#
# Caught the pre-v1.1.5 regression where runner-python:3.12 silently shipped
# Debian's python3 = 3.11.2. The Dockerfile declared ARG PYTHON_VERSION=3.12
# but never used it in the install command, so every "3.12" image we ever
# published actually ran 3.11. Build-time assertions now exist in the
# Dockerfiles, but this runtime check is defense-in-depth — if anyone in
# the future bypasses the build-time check, this catches it from outside.
#
# Reads ACCEPTANCE_LANG / ACCEPTANCE_LANG_VERSION (injected by
# docker-compose.acceptance.yml) and asks the actual runtime what it is.
source "$(dirname "$0")/../lib.sh"

LANG_NAME="${ACCEPTANCE_LANG:-}"
LANG_VER="${ACCEPTANCE_LANG_VERSION:-}"

if [ -z "$LANG_NAME" ] || [ -z "$LANG_VER" ]; then
    skip H07 "runtime version check" "ACCEPTANCE_LANG / ACCEPTANCE_LANG_VERSION not set"
    summary
    exit 0
fi

case "$LANG_NAME" in
    node)
        if ! command -v node >/dev/null 2>&1; then
            fail H07 "node binary not present in node:$LANG_VER image"
            summary; exit 0
        fi
        actual=$(node -p 'process.versions.node.split(".")[0]')
        if [ "$actual" = "$LANG_VER" ]; then
            pass H07 "node major version is $actual (matches tag $LANG_VER)"
        else
            fail H07 "node major is $actual but image tag claims $LANG_VER"
        fi
        ;;
    python)
        if ! command -v python3 >/dev/null 2>&1; then
            fail H07 "python3 not present in python:$LANG_VER image"
            summary; exit 0
        fi
        actual=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [ "$actual" = "$LANG_VER" ]; then
            pass H07 "python minor version is $actual (matches tag $LANG_VER)"
        else
            fail H07 "python minor is $actual but image tag claims $LANG_VER"
        fi
        ;;
    rust)
        if ! command -v rustc >/dev/null 2>&1; then
            fail H07 "rustc not present in rust:$LANG_VER image"
            summary; exit 0
        fi
        # Rust ships as channel name (stable/beta/nightly) OR explicit version.
        # `rustc --version` prints e.g. "rustc 1.78.0 (...)". We accept either
        # the named channel matching exactly or the version starting with
        # the expected prefix.
        actual=$(rustc --version | awk '{print $2}')
        if [ "$LANG_VER" = "stable" ] || [ "$LANG_VER" = "beta" ] || [ "$LANG_VER" = "nightly" ]; then
            # Channel — verify rustup says we're on that channel
            channel=$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' | cut -d'-' -f1)
            if [ "$channel" = "$LANG_VER" ]; then
                pass H07 "rust channel is $channel (matches tag $LANG_VER), version $actual"
            else
                fail H07 "rust channel is $channel but image tag claims $LANG_VER"
            fi
        else
            # Explicit version pin
            if echo "$actual" | grep -qE "^${LANG_VER}(\.|\$)"; then
                pass H07 "rust version is $actual (matches tag prefix $LANG_VER)"
            else
                fail H07 "rust version is $actual but image tag claims $LANG_VER"
            fi
        fi
        ;;
    *)
        fail H07 "unknown ACCEPTANCE_LANG: $LANG_NAME"
        ;;
esac

summary
