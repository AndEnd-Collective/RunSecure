#!/usr/bin/env python3
"""Move the `nightly` tags to the digests in a release image manifest.

publish-images.yml pushes every image under its `<version>-canary` tag so the
Grype jobs can scan the exact digest that was pushed. The mutable `nightly`
tags are a different matter: they are what people pull without pinning, so
they must only ever point at a digest whose scans passed. This script runs in
a job that needs every scan job, and retags by digest, server side, from the
release manifest the same run produced.

Manifest keys map to tags as follows:

    base                -> base:nightly
    proxy               -> proxy:nightly
    node-24             -> node:nightly-24
    node-build-24       -> node-build:nightly-24
    python-3.12         -> python:nightly-3.12
    rust-build-stable   -> rust-build:nightly-stable
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REFERENCE = re.compile(
    r"^(?P<repository>ghcr\.io/andend-collective/runsecure/"
    r"(?P<package>base|node(?:-build)?|orchestrator|proxy|"
    r"python(?:-build)?|rust(?:-build)?|socket-proxy))"
    r"@sha256:[0-9a-f]{64}$"
)
VARIANT = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.]*$")


def nightly_targets(manifest: dict[str, object]) -> list[tuple[str, str]]:
    """Return (target tag, source digest reference) pairs, sorted by key."""
    images = manifest.get("images")
    if not isinstance(images, dict) or not images:
        raise ValueError("manifest has no images")

    pairs: list[tuple[str, str]] = []
    for key in sorted(images):
        reference = images[key]
        if not isinstance(key, str) or not isinstance(reference, str):
            raise ValueError(f"{key!r}: image entries must be strings")
        match = REFERENCE.fullmatch(reference)
        if match is None:
            raise ValueError(f"{key}: invalid immutable image reference")
        package = match.group("package")
        if key == package:
            tag = "nightly"
        elif key.startswith(f"{package}-"):
            variant = key.removeprefix(f"{package}-")
            if not VARIANT.fullmatch(variant):
                raise ValueError(f"{key}: invalid image variant {variant!r}")
            tag = f"nightly-{variant}"
        else:
            raise ValueError(f"{key}: key does not belong to package {package}")
        pairs.append((f"{match.group('repository')}:{tag}", reference))

    targets = [target for target, _ in pairs]
    if len(set(targets)) != len(targets):
        raise ValueError("two manifest entries map to the same nightly tag")
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="print the planned retags instead of running them",
    )
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not a JSON object")
        pairs = nightly_targets(manifest)
    except (OSError, ValueError) as error:
        print(f"nightly tag error: {error}", file=sys.stderr)
        return 1

    for target, source in pairs:
        if args.print_only:
            print(f"{target} {source}")
            continue
        result = subprocess.run(
            ["docker", "buildx", "imagetools", "create", "--tag", target, source],
            check=False,
        )
        if result.returncode != 0:
            print(f"nightly tag error: retag of {target} failed", file=sys.stderr)
            return 1
        print(f"tagged {target} -> {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
