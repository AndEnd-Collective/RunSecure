#!/usr/bin/env python3
"""Build the published dependency status under .security/.

Inputs are produced by .github/workflows/security-status.yml:

  - one CycloneDX SBOM per Go module (cdxgen), with its dependency graph
  - one CycloneDX VDR per module (OWASP dep-scan): the SBOM plus the known
    vulnerabilities that apply to it
  - .security/upstreams.yml, the hand-maintained registry of every upstream
    RunSecure relies on

Outputs, all deterministic so the files only change when the facts change:

  sbom/<module>.cdx.json   normalised SBOM
  vulnerabilities.json     every advisory dep-scan matched, machine-readable
  dependencies.md          every dependency, with how far it is from our code
  STATUS.md                the summary a person reads

"Party" language used in the output: our own code is the first party; a
module we import directly is a third-party dependency (depth 1); a module that
one of those imports is a fourth-party dependency (depth 2); anything further
is listed with its depth.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "none", "unknown"]
ARG_LINE = re.compile(r"^ARG\s+([A-Z0-9_]+)=(\S+)\s*$", re.MULTILINE)
FROM_LINE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", re.MULTILINE)
GOLANG_PURL = re.compile(r"^pkg:golang/(?P<path>[^@?#]+)(?:@(?P<version>[^?#]+))?")


# --------------------------------------------------------------------------
# SBOM handling
# --------------------------------------------------------------------------
def normalise_sbom(bom: dict[str, Any]) -> dict[str, Any]:
    """Keep what describes the dependency set; drop what changes every run."""
    root = bom.get("metadata", {}).get("component", {})
    components = []
    for component in bom.get("components", []):
        entry = {
            key: component[key]
            for key in ("type", "group", "name", "version", "purl", "bom-ref", "scope")
            if component.get(key) not in (None, "")
        }
        licenses = sorted(
            {
                (item.get("license") or {}).get("id") or (item.get("license") or {}).get("name") or item.get("expression") or ""
                for item in component.get("licenses", [])
            }
            - {""}
        )
        if licenses:
            entry["licenses"] = licenses
        components.append(entry)
    components.sort(key=lambda c: (c.get("purl") or c.get("bom-ref") or c.get("name") or ""))
    dependencies = sorted(
        (
            {"ref": d["ref"], "dependsOn": sorted(set(d.get("dependsOn", [])))}
            for d in bom.get("dependencies", [])
            if d.get("ref")
        ),
        key=lambda d: d["ref"],
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": bom.get("specVersion", "unknown"),
        "metadata": {
            "component": {
                key: root[key] for key in ("type", "name", "version", "purl", "bom-ref") if root.get(key) not in (None, "")
            }
        },
        "components": components,
        "dependencies": dependencies,
    }


def root_ref(bom: dict[str, Any]) -> str | None:
    component = bom.get("metadata", {}).get("component", {})
    return component.get("bom-ref") or component.get("purl")


def depths(bom: dict[str, Any]) -> tuple[dict[str, int], dict[str, str]]:
    """Shortest distance of every component from the module itself, and the
    parent on that shortest path."""
    graph = {d["ref"]: d.get("dependsOn", []) for d in bom.get("dependencies", [])}
    start = root_ref(bom)
    depth: dict[str, int] = {}
    parent: dict[str, str] = {}
    if start is None or start not in graph:
        return depth, parent
    depth[start] = 0
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for child in sorted(graph.get(current, [])):
            if child not in depth:
                depth[child] = depth[current] + 1
                parent[child] = current
                queue.append(child)
    return depth, parent


def display(ref: str) -> str:
    match = GOLANG_PURL.match(ref)
    if match:
        version = match.group("version")
        return f"{match.group('path')}@{version}" if version else match.group("path")
    return re.sub(r"^pkg:[a-z]+/", "", ref)


def module_path(ref: str) -> str | None:
    match = GOLANG_PURL.match(ref)
    return match.group("path") if match else None


def chain(ref: str, parent: dict[str, str]) -> list[str]:
    path = [ref]
    while path[-1] in parent:
        path.append(parent[path[-1]])
    return list(reversed(path))


# --------------------------------------------------------------------------
# Upstream registry
# --------------------------------------------------------------------------
def upstream_for(path: str | None, registry: dict[str, Any]) -> dict[str, Any] | None:
    if not path:
        return None
    lowered = path.lower()
    best = None
    for entry in registry.get("go_modules", []):
        prefix = entry["prefix"].lower()
        if lowered.startswith(prefix) and (best is None or len(prefix) > len(best["prefix"])):
            best = entry
    return best


def pinned_components(registry: dict[str, Any], repo_root: Path) -> list[dict[str, str]]:
    rows = []
    for entry in registry.get("pinned_components", []):
        text = (repo_root / entry["file"]).read_text(encoding="utf-8")
        if "arg" in entry:
            values = [value for name, value in ARG_LINE.findall(text) if name == entry["arg"]]
            if not values:
                raise ValueError(f"{entry['file']}: no ARG {entry['arg']} for '{entry['name']}'")
            pin = f"`{entry['arg']}={values[0]}`"
        else:
            images = [image for image in FROM_LINE.findall(text) if image.split(":")[0].split("@")[0] == entry["from"]]
            if not images:
                raise ValueError(f"{entry['file']}: no FROM {entry['from']} for '{entry['name']}'")
            image = images[0]
            tag, _, digest = image.partition("@")
            pin = f"`{tag}`" + (f" @ `{digest[:19]}…`" if digest else "")
        rows.append({**entry, "pin": pin})
    return rows


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------
def severity_of(vulnerability: dict[str, Any]) -> str:
    found = [str(r.get("severity", "unknown")).lower() for r in vulnerability.get("ratings", [])]
    found = [s if s in SEVERITY_ORDER else "unknown" for s in found] or ["unknown"]
    return min(found, key=SEVERITY_ORDER.index)


def collect_vulnerabilities(
    module: str, vdr: dict[str, Any], bom: dict[str, Any], registry: dict[str, Any]
) -> list[dict[str, Any]]:
    depth, parent = depths(bom)
    rows = []
    for vulnerability in vdr.get("vulnerabilities", []):
        properties = {p.get("name"): p.get("value") for p in vulnerability.get("properties", [])}
        for affected in vulnerability.get("affects", []):
            ref = affected.get("ref", "")
            upstream = upstream_for(module_path(ref), registry)
            rows.append(
                {
                    "id": vulnerability.get("id", "unknown"),
                    "severity": severity_of(vulnerability),
                    "module": module,
                    "package": display(ref),
                    "purl": ref,
                    "depth": depth.get(ref),
                    "path": [display(step) for step in chain(ref, parent)] if ref in depth else [],
                    "recommendation": (vulnerability.get("recommendation") or "").strip(),
                    "insights": properties.get("depscan:insights") or "",
                    "prioritized": properties.get("depscan:prioritized") == "true",
                    "upstream": upstream["upstream"] if upstream else None,
                    "tracker": upstream["tracker"] if upstream else None,
                }
            )
    rows.sort(key=lambda r: (SEVERITY_ORDER.index(r["severity"]), r["id"], r["module"], r["package"]))
    return rows


VERDICT_TEXT = {
    "false_positive": "False positive",
    "not_applicable": "Not applicable",
    "not_exploitable": "Not exploitable",
    "accepted": "Accepted risk",
}


def apply_assessments(
    vulnerabilities: list[dict[str, Any]], assessments: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach the reviewed verdict to each match; return assessments that
    matched nothing (stale entries)."""
    used: set[int] = set()
    for vulnerability in vulnerabilities:
        path = (module_path(vulnerability["purl"]) or "").lower()
        vulnerability["assessment"] = None
        for index, assessment in enumerate(assessments):
            if assessment["verdict"] not in VERDICT_TEXT:
                raise ValueError(f"assessment {assessment['id']}: unknown verdict {assessment['verdict']!r}")
            if assessment["id"] == vulnerability["id"] and path.startswith(assessment["package"].lower()):
                vulnerability["assessment"] = {
                    "verdict": assessment["verdict"],
                    "reason": " ".join(str(assessment["reason"]).split()),
                    "reference": assessment["reference"],
                }
                used.add(index)
                break
    return [a for index, a in enumerate(assessments) if index not in used]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def party(depth: int | None) -> str:
    if depth is None:
        return "not linked"
    if depth == 1:
        return "third party (direct)"
    if depth == 2:
        return "fourth party"
    return f"depth {depth}"


def cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_dependencies(modules: dict[str, dict[str, Any]], registry: dict[str, Any]) -> str:
    out = [
        "# Dependencies",
        "",
        "Generated by `infra/scripts/security-status.py`. Do not edit.",
        "",
        "Every Go module RunSecure builds, and every module it pulls in. *Distance* is the",
        "shortest import path from our code: 1 is a module we import ourselves (third party),",
        "2 is a module one of those imports (fourth party), and so on. *Upstream* comes from",
        "[upstreams.yml](upstreams.yml).",
        "",
    ]
    for module in sorted(modules):
        bom = modules[module]
        depth, parent = depths(bom)
        out += [f"## `{module}`", ""]
        rows = []
        for component in bom.get("components", []):
            ref = component.get("bom-ref") or component.get("purl") or ""
            upstream = upstream_for(module_path(ref) or component.get("name"), registry)
            via = [display(step) for step in chain(ref, parent)][1:-1] if ref in depth else []
            rows.append(
                (
                    depth.get(ref, 99),
                    display(ref) or component.get("name", ""),
                    party(depth.get(ref)),
                    " → ".join(via) if via else ("" if depth.get(ref) == 1 else "—"),
                    upstream["upstream"] if upstream else "**not registered**",
                )
            )
        if not rows:
            out += ["No third-party dependencies.", ""]
            continue
        out += ["| Dependency | Distance | Reached through | Upstream |", "|---|---|---|---|"]
        for _, name, distance, via, upstream in sorted(rows):
            out.append(f"| `{cell(name)}` | {distance} | {cell(via)} | {cell(upstream)} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_status(
    modules: dict[str, dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    registry: dict[str, Any],
    pins: list[dict[str, str]],
    repository: str,
    stale_assessments: list[dict[str, Any]],
) -> str:
    out = [
        "# Dependency and vulnerability status",
        "",
        "Generated by `infra/scripts/security-status.py` from a nightly",
        "[OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) run. Do not edit.",
        "This file changes only when the facts change; the",
        f"[workflow runs](https://github.com/{repository}/actions/workflows/security-status.yml)",
        "show when it was last checked. How to read it: [README.md](README.md).",
        "",
        "## Summary",
        "",
        "| Module | Dependencies | Third party (direct) | Fourth party | Deeper | Open advisories | Assessed |",
        "|---|---|---|---|---|---|---|",
    ]
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    unregistered: set[str] = set()
    for module in sorted(modules):
        bom = modules[module]
        depth, _ = depths(bom)
        refs = [c.get("bom-ref") or c.get("purl") or "" for c in bom.get("components", [])]
        direct = sum(1 for r in refs if depth.get(r) == 1)
        fourth = sum(1 for r in refs if depth.get(r) == 2)
        deeper = sum(1 for r in refs if depth.get(r, 0) > 2)
        mine = [v for v in vulnerabilities if v["module"] == module]
        assessed = sum(1 for v in mine if v["assessment"])
        mine = [v for v in mine if not v["assessment"]]
        counts = {s: sum(1 for v in mine if v["severity"] == s) for s in totals}
        for severity, count in counts.items():
            totals[severity] += count
        advisories = ", ".join(f"{count} {severity}" for severity, count in counts.items() if count) or "none"
        out.append(f"| `{module}` | {len(refs)} | {direct} | {fourth} | {deeper} | {advisories} | {assessed or 'none'} |")
        for component in bom.get("components", []):
            ref = component.get("bom-ref") or component.get("purl") or ""
            path = module_path(ref)
            if path and upstream_for(path, registry) is None:
                unregistered.add(path)
    out.append("")

    open_matches = [v for v in vulnerabilities if not v["assessment"]]
    assessed_matches = [v for v in vulnerabilities if v["assessment"]]

    def reach(v: dict[str, Any]) -> str:
        if not v["path"]:
            return "not in the dependency graph"
        return " → ".join(v["path"][1:]) + f" ({party(v['depth'])})"

    def fixer(v: dict[str, Any]) -> str:
        return f"[{cell(v['upstream'])}]({v['tracker']})" if v["upstream"] else "**not registered**"

    out += ["## Open advisories", ""]
    if not open_matches:
        out += ["None. Every advisory dep-scan matched has a reviewed assessment below, or nothing matched.", ""]
    else:
        out += [
            "Matches that nobody has assessed yet. A row here is a match on a package and",
            "version, not proof of exposure: see",
            "[README.md](README.md#what-a-row-under-open-advisories-means) for how each one is",
            "resolved. Advisories with no upgrade path get a written impact analysis on an",
            f"[issue](https://github.com/{repository}/issues?q=is%3Aissue+label%3Asecurity-advisory).",
            "",
            "| Advisory | Severity | Package | Module | How it reaches us | Upstream that fixes it | dep-scan guidance |",
            "|---|---|---|---|---|---|---|",
        ]
        for v in open_matches:
            guidance = "; ".join(part for part in (v["recommendation"], v["insights"]) if part) or "—"
            out.append(
                f"| {cell(v['id'])} | {v['severity']} | `{cell(v['package'])}` | `{v['module']}` | "
                f"{cell(reach(v))} | {fixer(v)} | {cell(guidance)} |"
            )
        out.append("")

    out += ["## Assessed advisories", ""]
    if not assessed_matches:
        out += ["None.", ""]
    else:
        out += [
            "Matches a maintainer has worked through. The conclusions are kept in",
            "[assessments.yml](assessments.yml); each has a reference you can check.",
            "",
            "| Advisory | Severity | Package | Module | How it reaches us | Upstream | Assessment |",
            "|---|---|---|---|---|---|---|",
        ]
        for v in assessed_matches:
            a = v["assessment"]
            verdict = f"**{VERDICT_TEXT[a['verdict']]}.** {cell(a['reason'])} ([reference]({a['reference']}))"
            out.append(
                f"| {cell(v['id'])} | {v['severity']} | `{cell(v['package'])}` | `{v['module']}` | "
                f"{cell(reach(v))} | {fixer(v)} | {verdict} |"
            )
        out.append("")
    if stale_assessments:
        out += [
            "### Assessments that no longer match anything",
            "",
            "Remove these from [assessments.yml](assessments.yml):",
            "",
        ] + [f"- {a['id']} on `{a['package']}`" for a in stale_assessments] + [""]

    out += [
        "## Pinned components",
        "",
        "Software fetched into the images by an explicit pin, and who is responsible for it.",
        "",
        "| Component | Pin | Upstream | Why it is trusted |",
        "|---|---|---|---|",
    ]
    for pin in pins:
        out.append(
            f"| {cell(pin['name'])} | {pin['pin']} in `{pin['file']}` | "
            f"[{cell(pin['upstream'])}]({pin['tracker']}) | {cell(pin['why'])} |"
        )
    out.append("")

    out += ["## Upstreams not in the registry", ""]
    if unregistered:
        out += [
            "These modules appear in a dependency graph but have no entry in",
            "[upstreams.yml](upstreams.yml). They arrive only through another module's build or",
            "test requirements (they are not named in any of our `go.mod` files, which the test",
            "suite checks). Add an entry if one becomes a real dependency.",
            "",
        ] + [f"- `{path}`" for path in sorted(unregistered)] + [""]
    else:
        out += ["None. Every module in every dependency graph maps to a registered upstream.", ""]
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def build(args: argparse.Namespace) -> None:
    registry = yaml.safe_load(args.upstreams.read_text(encoding="utf-8"))
    assessments = (yaml.safe_load(args.assessments.read_text(encoding="utf-8")) or {}).get("assessments") or []
    modules: dict[str, dict[str, Any]] = {}
    vulnerabilities: list[dict[str, Any]] = []
    for sbom_path in sorted(args.sbom_dir.glob("*.cdx.json")):
        slug = sbom_path.name.removesuffix(".cdx.json")
        module = slug.replace("__", "/")
        bom = normalise_sbom(json.loads(sbom_path.read_text(encoding="utf-8")))
        modules[module] = bom
        vdr_path = args.vdr_dir / f"{slug}.vdr.json"
        if not vdr_path.is_file():
            raise ValueError(f"no dep-scan report for {module} ({vdr_path.name})")
        vdr = json.loads(vdr_path.read_text(encoding="utf-8"))
        vulnerabilities += collect_vulnerabilities(module, vdr, bom, registry)
    if not modules:
        raise ValueError(f"no SBOMs found in {args.sbom_dir}")

    stale = apply_assessments(vulnerabilities, assessments)

    out = args.output_dir
    (out / "sbom").mkdir(parents=True, exist_ok=True)
    for previous in (out / "sbom").glob("*.cdx.json"):
        previous.unlink()
    for module, bom in modules.items():
        target = out / "sbom" / f"{module.replace('/', '__')}.cdx.json"
        target.write_text(json.dumps(bom, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "vulnerabilities.json").write_text(
        json.dumps(vulnerabilities, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "dependencies.md").write_text(render_dependencies(modules, registry), encoding="utf-8")
    pins = pinned_components(registry, args.repo_root)
    (out / "STATUS.md").write_text(
        render_status(modules, vulnerabilities, registry, pins, args.repository, stale), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sbom-dir", required=True, type=Path)
    parser.add_argument("--vdr-dir", required=True, type=Path)
    parser.add_argument("--upstreams", required=True, type=Path)
    parser.add_argument("--assessments", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        build(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"security status error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
