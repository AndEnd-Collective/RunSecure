#!/usr/bin/env python3
"""Promote one verified manifest behind aggregate, fail-closed preflight."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

IMAGE_PREFIX = "ghcr.io/andend-collective/runsecure"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MISSING = re.compile(r"(?:manifest unknown|not found)", re.IGNORECASE)
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True)
class Promotion:
    manifest_key: str
    package: str
    canary_suffix: str
    stable_suffix: str
    alias: str


PROMOTIONS = (
    Promotion("base", "base", "", "", "latest"),
    Promotion("proxy", "proxy", "", "", "latest"),
    Promotion("orchestrator", "orchestrator", "", "", "latest"),
    Promotion("socket-proxy", "socket-proxy", "", "", "latest"),
    Promotion("node-build-24", "node-build", "-24", "-24", "latest-24"),
    Promotion("node-build-22", "node-build", "-22", "-22", "latest-22"),
    Promotion(
        "python-build-3.12",
        "python-build",
        "-3.12",
        "-3.12",
        "latest-3.12",
    ),
    Promotion(
        "rust-build-stable",
        "rust-build",
        "-stable",
        "-stable",
        "latest-stable",
    ),
    Promotion("node-24", "node", "-24", "-24", "latest-24"),
    Promotion("node-22", "node", "-22", "-22", "latest-22"),
    Promotion("python-3.12", "python", "-3.12", "-3.12", "latest-3.12"),
    Promotion("rust-stable", "rust", "-stable", "-stable", "latest-stable"),
)


class PromotionError(RuntimeError):
    """A registry or manifest condition makes promotion unsafe."""


@dataclass
class ResolvedPromotion:
    definition: Promotion
    source: str
    expected_digest: str
    canary: str
    stable: str
    alias: str
    stable_digest: str | None = None
    alias_digest: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--release", required=True)
    return parser.parse_args()


def run_imagetools(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "buildx", "imagetools", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def inspect_digest(reference: str, *, missing_ok: bool = False) -> str | None:
    result = run_imagetools("inspect", reference, "--format", "{{.Manifest.Digest}}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if missing_ok and MISSING.search(detail):
            return None
        raise PromotionError(f"cannot inspect {reference}: {detail or 'unknown error'}")

    digest = result.stdout.strip()
    if DIGEST.fullmatch(digest) is None:
        raise PromotionError(
            f"{reference}: registry returned invalid digest {digest!r}"
        )
    return digest


def create_tag(target: str, source: str) -> None:
    result = run_imagetools("create", "--tag", target, source)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise PromotionError(
            f"cannot promote {source} to {target}: {detail or 'unknown error'}"
        )


def load_plan(path: Path, release: str) -> list[ResolvedPromotion]:
    if SEMVER.fullmatch(release) is None:
        raise PromotionError("release must be an exact semver without v")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PromotionError(f"cannot read release manifest: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("release") != release:
        raise PromotionError("manifest release does not match the requested release")
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != {
        promotion.manifest_key for promotion in PROMOTIONS
    }:
        raise PromotionError("manifest image set does not match the promotion plan")

    plan: list[ResolvedPromotion] = []
    for promotion in PROMOTIONS:
        source = images[promotion.manifest_key]
        prefix = f"{IMAGE_PREFIX}/{promotion.package}@"
        if not isinstance(source, str) or not source.startswith(prefix):
            raise PromotionError(
                f"{promotion.manifest_key}: source package does not match the plan"
            )
        expected_digest = source.removeprefix(prefix)
        if DIGEST.fullmatch(expected_digest) is None:
            raise PromotionError(
                f"{promotion.manifest_key}: source digest is not immutable"
            )
        package_ref = f"{IMAGE_PREFIX}/{promotion.package}"
        plan.append(
            ResolvedPromotion(
                definition=promotion,
                source=source,
                expected_digest=expected_digest,
                canary=f"{package_ref}:{release}-canary{promotion.canary_suffix}",
                stable=f"{package_ref}:{release}{promotion.stable_suffix}",
                alias=f"{package_ref}:{promotion.alias}",
            )
        )
    return plan


def preflight(plan: list[ResolvedPromotion]) -> None:
    failures: list[str] = []

    for item in plan:
        for label, reference in (("source", item.source), ("canary", item.canary)):
            try:
                actual = inspect_digest(reference)
                if actual != item.expected_digest:
                    failures.append(
                        f"{item.definition.manifest_key}: {label} digest moved "
                        f"(expected {item.expected_digest}, got {actual})"
                    )
            except PromotionError as error:
                failures.append(str(error))

    for item in plan:
        try:
            item.stable_digest = inspect_digest(item.stable, missing_ok=True)
            if item.stable_digest not in (None, item.expected_digest):
                failures.append(
                    f"{item.definition.manifest_key}: immutable version tag already "
                    f"points at {item.stable_digest}"
                )
        except PromotionError as error:
            failures.append(str(error))

    for item in plan:
        try:
            item.alias_digest = inspect_digest(item.alias, missing_ok=True)
        except PromotionError as error:
            failures.append(str(error))

    if failures:
        detail = "\n".join(f"- {failure}" for failure in failures)
        raise PromotionError(
            "release promotion preflight failed; no tags were changed:\n" + detail
        )
    print(f"Preflighted {len(plan)} immutable sources and destination tag sets.")


def promote(plan: list[ResolvedPromotion]) -> None:
    # Publish immutable version tags first. Floating aliases remain untouched
    # until the complete versioned set is present and verified.
    for item in plan:
        if item.stable_digest != item.expected_digest:
            create_tag(item.stable, item.source)

    for item in plan:
        actual = inspect_digest(item.stable)
        if actual != item.expected_digest:
            raise PromotionError(
                f"{item.definition.manifest_key}: version tag verification failed"
            )

    attempted_aliases: list[ResolvedPromotion] = []
    try:
        for item in plan:
            if item.alias_digest != item.expected_digest:
                # Record the attempt first: a registry can apply a tag update
                # and still return an error while finalizing the request.
                attempted_aliases.append(item)
                create_tag(item.alias, item.source)

        for item in plan:
            actual = inspect_digest(item.alias)
            if actual != item.expected_digest:
                raise PromotionError(
                    f"{item.definition.manifest_key}: alias verification failed"
                )
    except PromotionError as error:
        rollback_failures = rollback_aliases(attempted_aliases)
        if rollback_failures:
            detail = "; ".join(rollback_failures)
            raise PromotionError(
                f"{error}; alias rollback incomplete: {detail}"
            ) from error
        raise PromotionError(f"{error}; changed aliases were restored") from error
    print(f"Promoted and verified {len(plan)} release image sets.")


def rollback_aliases(items: list[ResolvedPromotion]) -> list[str]:
    """Best-effort restore aliases, without deleting registry manifests."""
    failures: list[str] = []
    for item in reversed(items):
        prior = item.alias_digest
        if prior is None:
            try:
                current = inspect_digest(item.alias, missing_ok=True)
            except PromotionError as error:
                failures.append(str(error))
                continue
            if current is not None:
                # buildx has no safe tag-only delete. Deleting the manifest by
                # digest can remove shared version tags, so leave an explicit
                # residual error for operator repair instead.
                failures.append(
                    f"{item.alias}: newly created alias cannot be safely deleted"
                )
            continue

        package_ref = item.source.rsplit("@", 1)[0]
        try:
            create_tag(item.alias, f"{package_ref}@{prior}")
            if inspect_digest(item.alias) != prior:
                failures.append(f"{item.alias}: restored digest did not verify")
        except PromotionError as error:
            failures.append(str(error))
    return failures


def main() -> int:
    args = parse_args()
    try:
        plan = load_plan(args.manifest, args.release)
        preflight(plan)
        promote(plan)
    except PromotionError as error:
        print(f"release promotion error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
