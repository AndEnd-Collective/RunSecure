#!/usr/bin/env python3
"""Validate the host credential bind in a rendered orchestrator Compose config.

Covers both auth types. The scope's credential is either a PAT
(auth.type: pat) or a GitHub App private key (auth.type: github_app); both are
delivered through the same auth-secret-init service, so the same host checks
apply to each. See issue #64.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import NoReturn

# Basenames auth-secret-init is allowed to write into the secret volume. Kept
# in sync with the case statement in compose.scope.yml.
VALID_SECRET_NAMES = frozenset({"runsecure-pat", "runsecure-app-private-key"})


def fail(message: str) -> NoReturn:
    """Exit with a redacted operator-facing validation error."""
    print(f"[RunSecure] ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Validate the exact host bind source without following symlinks."""
    if len(sys.argv) != 3:
        fail("usage: validate-compose-auth-secret.py <sentinel> <auth-secret-name>")

    sentinel_arg, secret_name = sys.argv[1], sys.argv[2]
    if secret_name not in VALID_SECRET_NAMES:
        fail(f"unsupported auth secret name: {secret_name}")

    try:
        rendered = json.load(sys.stdin)
        init = rendered["services"]["auth-secret-init"]
        mount = next(
            item
            for item in init["volumes"]
            if item.get("target") == "/host-auth-secret"
        )
    except (
        AttributeError,
        KeyError,
        StopIteration,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        fail(
            "could not resolve the auth-secret-init host bind from rendered "
            f"Compose: {exc}"
        )

    source = mount.get("source")
    if mount.get("type") != "bind" or not isinstance(source, str) or not source:
        fail("auth-secret-init /host-auth-secret must resolve to a host bind source")

    try:
        info = os.lstat(source)
    except OSError as exc:
        fail(f"auth secret source cannot be inspected: {exc}")

    if stat.S_ISLNK(info.st_mode):
        fail(f"auth secret source must not be a symlink: {source}")
    if not stat.S_ISREG(info.st_mode):
        fail(f"auth secret source must be a regular file: {source}")
    if info.st_uid != os.getuid():
        fail(
            "auth secret source must be owned by the invoking UID "
            f"{os.getuid()} (got {info.st_uid}): {source}"
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o400:
        fail(f"auth secret source must be mode 0400 (got {mode:04o}): {source}")

    environment = init.get("environment", {})
    if environment.get("RUNSECURE_AUTH_SECRET_HOST_VALIDATED") != sentinel_arg:
        fail("rendered auth-secret-init validation sentinel is missing or invalid")

    # The rendered name decides the filename written into the shared secret
    # volume, and the orchestrator reads that exact path from the scope file.
    # A mismatch here means the stack would start with the credential under a
    # name the orchestrator is not looking for.
    rendered_name = environment.get("RUNSECURE_AUTH_SECRET_NAME")
    if rendered_name != secret_name:
        fail(
            "rendered auth secret name does not match the scope's auth.type "
            f"(expected {secret_name}, got {rendered_name})"
        )


if __name__ == "__main__":
    main()
