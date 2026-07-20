#!/usr/bin/env python3
"""Validate an immutable RunSecure release manifest and its provenance."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_IMAGES = {
    "base": "base",
    "node-22": "node",
    "node-24": "node",
    "orchestrator": "orchestrator",
    "proxy": "proxy",
    "python-3.12": "python",
    "rust-stable": "rust",
    "socket-proxy": "socket-proxy",
}
REFERENCE = re.compile(
    r"^ghcr\.io/andend-collective/runsecure/"
    r"(?P<package>base|node|orchestrator|proxy|python|rust|socket-proxy)"
    r"@sha256:[0-9a-f]{64}$"
)
RELEASE = re.compile(r"^(?:[0-9]+\.[0-9]+\.[0-9]+|manual-build)$")
BUILD_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-release")
    parser.add_argument("--expected-build-sha")
    parser.add_argument("--expected-publish-run-id", type=int)
    return parser.parse_args()


def read_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value


def validate_manifest(manifest: dict[str, object], args: argparse.Namespace) -> None:
    expected_fields = {
        "schema_version",
        "release",
        "build_sha",
        "publish_run_id",
        "images",
    }
    if set(manifest) != expected_fields:
        raise ValueError("manifest fields do not match schema version 1")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported manifest schema version")

    release = manifest["release"]
    build_sha = manifest["build_sha"]
    publish_run_id = manifest["publish_run_id"]
    images = manifest["images"]
    if not isinstance(release, str) or RELEASE.fullmatch(release) is None:
        raise ValueError("invalid release")
    if not isinstance(build_sha, str) or BUILD_SHA.fullmatch(build_sha) is None:
        raise ValueError("invalid build SHA")
    if not isinstance(publish_run_id, int) or isinstance(publish_run_id, bool):
        raise ValueError("invalid Publish Images run ID")
    if publish_run_id <= 0:
        raise ValueError("invalid Publish Images run ID")
    if not isinstance(images, dict) or set(images) != set(EXPECTED_IMAGES):
        raise ValueError("release image set is incomplete or unexpected")

    for key, package in EXPECTED_IMAGES.items():
        reference = images[key]
        if not isinstance(reference, str):
            raise ValueError(f"{key}: image reference must be a string")
        match = REFERENCE.fullmatch(reference)
        if match is None or match.group("package") != package:
            raise ValueError(f"{key}: invalid immutable image reference")

    if args.expected_release is not None and release != args.expected_release:
        raise ValueError("release does not match the requested version")
    if args.expected_build_sha is not None and build_sha != args.expected_build_sha:
        raise ValueError("build SHA does not match the Publish Images run")
    if (
        args.expected_publish_run_id is not None
        and publish_run_id != args.expected_publish_run_id
    ):
        raise ValueError("manifest does not match the Publish Images run ID")


def main() -> int:
    args = parse_args()
    try:
        validate_manifest(read_manifest(args.manifest), args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release manifest verification error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
