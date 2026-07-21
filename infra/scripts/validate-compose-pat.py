#!/usr/bin/env python3
"""Validate the host PAT bind in a rendered orchestrator Compose config."""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import NoReturn


def fail(message: str) -> NoReturn:
    """Exit with a redacted operator-facing validation error."""
    print(f"[RunSecure] ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Validate the exact host bind source without following symlinks."""
    if len(sys.argv) != 2:
        fail("validation sentinel argument is required")

    try:
        rendered = json.load(sys.stdin)
        pat_init = rendered["services"]["pat-init"]
        mount = next(
            item for item in pat_init["volumes"] if item.get("target") == "/host-pat"
        )
    except (
        AttributeError,
        KeyError,
        StopIteration,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        fail(f"could not resolve the pat-init host bind from rendered Compose: {exc}")

    source = mount.get("source")
    if mount.get("type") != "bind" or not isinstance(source, str) or not source:
        fail("pat-init /host-pat must resolve to a host bind source")

    try:
        info = os.lstat(source)
    except OSError as exc:
        fail(f"PAT source cannot be inspected: {exc}")

    if stat.S_ISLNK(info.st_mode):
        fail(f"PAT source must not be a symlink: {source}")
    if not stat.S_ISREG(info.st_mode):
        fail(f"PAT source must be a regular file: {source}")
    if info.st_uid != os.getuid():
        fail(
            "PAT source must be owned by the invoking UID "
            f"{os.getuid()} (got {info.st_uid}): {source}"
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o400:
        fail(f"PAT source must be mode 0400 (got {mode:04o}): {source}")

    sentinel = pat_init.get("environment", {}).get("RUNSECURE_PAT_HOST_VALIDATED")
    if sentinel != sys.argv[1]:
        fail("rendered pat-init validation sentinel is missing or invalid")


if __name__ == "__main__":
    main()
