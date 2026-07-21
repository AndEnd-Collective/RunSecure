#!/usr/bin/env python3
"""Build a fail-closed release image manifest from build digest artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_IMAGES = {
    "release-digest-base": "base",
    "release-digest-node-build-22": "node-build",
    "release-digest-node-build-24": "node-build",
    "release-digest-node-22": "node",
    "release-digest-node-24": "node",
    "release-digest-orchestrator": "orchestrator",
    "release-digest-proxy": "proxy",
    "release-digest-python-build-3.12": "python-build",
    "release-digest-python-3.12": "python",
    "release-digest-rust-build-stable": "rust-build",
    "release-digest-rust-stable": "rust",
    "release-digest-socket-proxy": "socket-proxy",
}
REFERENCE = re.compile(
    r"^ghcr\.io/andend-collective/runsecure/"
    r"(?P<package>base|node(?:-build)?|orchestrator|proxy|"
    r"python(?:-build)?|rust(?:-build)?|socket-proxy)"
    r"@sha256:[0-9a-f]{64}$"
)
RELEASE = re.compile(r"^(?:[0-9]+\.[0-9]+\.[0-9]+|manual-build)$")
BUILD_SHA = re.compile(r"^[0-9a-f]{40,64}$")
PUBLISH_RUN_ID = re.compile(r"^[1-9][0-9]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", required=True)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--publish-run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("digest_files", nargs="+", type=Path)
    return parser.parse_args()


def read_reference(path: Path) -> str:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(lines) != 1:
        raise ValueError(f"{path}: expected exactly one image digest reference")
    return lines[0]


def build_manifest(args: argparse.Namespace) -> dict[str, object]:
    if not RELEASE.fullmatch(args.release):
        raise ValueError(f"invalid release: {args.release}")
    if not BUILD_SHA.fullmatch(args.build_sha):
        raise ValueError(f"invalid build SHA: {args.build_sha}")
    if not PUBLISH_RUN_ID.fullmatch(args.publish_run_id):
        raise ValueError(f"invalid Publish Images run ID: {args.publish_run_id}")

    images: dict[str, str] = {}
    for path in args.digest_files:
        key = path.stem
        expected_package = EXPECTED_IMAGES.get(key)
        if expected_package is None:
            raise ValueError(f"unexpected digest artifact: {path.name}")
        if key in images:
            raise ValueError(f"duplicate digest artifact: {path.name}")

        reference = read_reference(path)
        match = REFERENCE.fullmatch(reference)
        if match is None:
            raise ValueError(f"{path}: invalid immutable image reference")
        if match.group("package") != expected_package:
            raise ValueError(
                f"{path}: expected package {expected_package}, "
                f"got {match.group('package')}"
            )
        images[key.removeprefix("release-digest-")] = reference

    expected_keys = {
        key.removeprefix("release-digest-") for key in EXPECTED_IMAGES
    }
    missing = sorted(expected_keys - images.keys())
    if missing:
        raise ValueError(f"missing release image digests: {', '.join(missing)}")

    return {
        "schema_version": 2,
        "release": args.release,
        "build_sha": args.build_sha,
        "publish_run_id": int(args.publish_run_id),
        "images": dict(sorted(images.items())),
    }


def main() -> int:
    args = parse_args()
    try:
        manifest = build_manifest(args)
    except (OSError, ValueError) as error:
        print(f"release manifest error: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
