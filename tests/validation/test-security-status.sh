#!/bin/bash
# ============================================================================
# RunSecure — supply-chain policy and the published status under .security/
# ============================================================================
# Three things are checked here.
#
#   Policy. "RunSecure only depends on well-known upstreams" is a claim made
#   in .security/README.md. It is true only while every Go module in every
#   go.mod, and every version pin in a Dockerfile, maps to an entry in
#   .security/upstreams.yml. A dependency from an unregistered upstream fails
#   this test.
#
#   The generator. infra/scripts/security-status.py turns SBOMs and OWASP
#   dep-scan reports into the published files. It is run here on fixtures:
#   distance from our code, upstream attribution, assessments, determinism.
#
#   The workflow. The job that runs third-party tools holds no credential;
#   the jobs that hold one run no third-party tool.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-security-status-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT

python3 - "$RUNSECURE_ROOT" "$tmp" <<'PY'
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

import yaml

root = pathlib.Path(sys.argv[1])
tmp = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("security_status", root / "infra/scripts/security-status.py")
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)

checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    checks += 1


registry = yaml.safe_load((root / ".security/upstreams.yml").read_text())
assessments = yaml.safe_load((root / ".security/assessments.yml").read_text())["assessments"]

# ---- policy: every Go module maps to a registered upstream -------------------
tracked = subprocess.run(
    ["git", "-C", str(root), "ls-files", "*go.mod"], check=True, capture_output=True, text=True
).stdout.split()
check(len(tracked) >= 7, f"expected the repository's Go modules, found {tracked}")
unregistered = {}
for gomod in tracked:
    in_block = False
    for line in (root / gomod).read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block and stripped and not stripped.startswith("//"):
            module = stripped.split()[0]
        elif stripped.startswith("require ") and "(" not in stripped:
            module = stripped.split()[1]
        else:
            continue
        if ss.upstream_for(module, registry) is None:
            unregistered.setdefault(module, gomod)
check(
    not unregistered,
    "Go modules with no entry in .security/upstreams.yml (add the upstream and say why it is trusted): "
    + ", ".join(f"{module} ({gomod})" for module, gomod in sorted(unregistered.items())),
)

for entry in registry["go_modules"]:
    for field in ("prefix", "upstream", "tracker", "why"):
        check(str(entry.get(field, "")).strip(), f"upstream {entry.get('prefix')}: missing '{field}'")
    check(entry["tracker"].startswith("https://"), f"upstream {entry['prefix']}: tracker must be an https URL")
prefixes = [entry["prefix"] for entry in registry["go_modules"]]
check(len(prefixes) == len(set(prefixes)), "duplicate prefix in upstreams.yml")

# ---- policy: every third-party version pin is registered --------------------
# ARGs that are not a third-party version: our own version, internal image
# references, and RUST_VERSION, a channel name resolved through RUST_STABLE_PIN.
NOT_THIRD_PARTY = {"BASE_TAG", "RUNSECURE_VERSION", "RUST_VERSION"}
registered_args = {(entry["file"], entry["arg"]) for entry in registry["pinned_components"] if "arg" in entry}
dockerfiles = [
    path
    for path in subprocess.run(
        ["git", "-C", str(root), "ls-files", "images", "infra"], check=True, capture_output=True, text=True
    ).stdout.split()
    if "dockerfile" in pathlib.Path(path).name.lower()
]
seen_args = set()
for dockerfile in dockerfiles:
    for name, _ in re.findall(r"^ARG\s+([A-Z0-9_]+)=(\S+)\s*$", (root / dockerfile).read_text(), re.MULTILINE):
        if re.search(r"_(VERSION|PIN|TAG)$", name) and name not in NOT_THIRD_PARTY:
            seen_args.add(name)
registered_names = {arg for _, arg in registered_args}
check(
    seen_args <= registered_names,
    f"version pins with no entry under pinned_components in upstreams.yml: {sorted(seen_args - registered_names)}",
)
pins = ss.pinned_components(registry, root)
check(len(pins) == len(registry["pinned_components"]), "every pinned component resolves to a pin in its Dockerfile")
for entry in registry["pinned_components"]:
    for field in ("name", "file", "upstream", "tracker", "why"):
        check(str(entry.get(field, "")).strip(), f"pinned component {entry.get('name')}: missing '{field}'")
    check(("arg" in entry) != ("from" in entry), f"pinned component {entry['name']}: exactly one of arg / from")

for entry in assessments:
    for field in ("id", "package", "verdict", "reason", "reference"):
        check(str(entry.get(field, "")).strip(), f"assessment {entry.get('id')}: missing '{field}'")
    check(entry["verdict"] in ss.VERDICT_TEXT, f"assessment {entry['id']}: unknown verdict")
    check(entry["reference"].startswith("https://"), f"assessment {entry['id']}: reference must be an https URL")

# ---- generator, on fixtures -------------------------------------------------
ROOT = "pkg:golang/example.test/app"
def purl(name, version="v1.0.0"):
    return f"pkg:golang/{name}@{version}"

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:changes-every-run",
    "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"type": "application", "name": "app", "bom-ref": ROOT}},
    "components": [
        {"type": "library", "name": "zeta", "bom-ref": purl("github.com/unknown/zeta"), "purl": purl("github.com/unknown/zeta")},
        {"type": "library", "name": "client-go", "bom-ref": purl("k8s.io/client-go"), "purl": purl("k8s.io/client-go"),
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"type": "library", "name": "net", "bom-ref": purl("golang.org/x/net", "v0.63.0"), "purl": purl("golang.org/x/net", "v0.63.0")},
        {"type": "library", "name": "text", "bom-ref": purl("golang.org/x/text"), "purl": purl("golang.org/x/text")},
        {"type": "library", "name": "orphan", "bom-ref": purl("gopkg.in/yaml.v3"), "purl": purl("gopkg.in/yaml.v3")},
    ],
    "dependencies": [
        {"ref": ROOT, "dependsOn": [purl("k8s.io/client-go"), purl("github.com/unknown/zeta")]},
        {"ref": purl("k8s.io/client-go"), "dependsOn": [purl("golang.org/x/net", "v0.63.0")]},
        {"ref": purl("golang.org/x/net", "v0.63.0"), "dependsOn": [purl("golang.org/x/text")]},
    ],
}
vdr = {
    "vulnerabilities": [
        {
            "id": "CVE-2023-44487",
            "ratings": [{"severity": "medium"}, {"severity": "high"}],
            "affects": [{"ref": purl("golang.org/x/net", "v0.63.0")}],
            "recommendation": "Update to version v9.",
            "properties": [{"name": "depscan:insights", "value": "Indirect dependency"}],
        },
        {
            "id": "CVE-2099-0001",
            "ratings": [{"severity": "critical"}],
            "affects": [{"ref": purl("github.com/unknown/zeta")}],
        },
    ]
}

normal = ss.normalise_sbom(bom)
check("serialNumber" not in normal and "timestamp" not in normal["metadata"], "normalised SBOM drops per-run fields")
check(len(normal["components"]) == len(bom["components"]), "no component is dropped")
check(normal["components"][0]["purl"] < normal["components"][-1]["purl"], "components are sorted")
check(next(c for c in normal["components"] if c["name"] == "client-go")["licenses"] == ["Apache-2.0"], "licenses are kept")

depth, parent = ss.depths(normal)
check(depth[purl("k8s.io/client-go")] == 1, "a module we import is at distance 1")
check(depth[purl("golang.org/x/net", "v0.63.0")] == 2, "a dependency of a dependency is at distance 2")
check(depth[purl("golang.org/x/text")] == 3, "distance keeps counting past fourth party")
check(purl("gopkg.in/yaml.v3") not in depth, "a component outside the graph has no distance")
check(ss.party(1) == "third party (direct)" and ss.party(2) == "fourth party" and ss.party(3) == "depth 3", "party wording")

check(ss.upstream_for("golang.org/x/net", registry)["upstream"].startswith("The Go project"), "x/net belongs to the Go project")
check(ss.upstream_for("k8s.io/client-go", registry)["upstream"].startswith("Kubernetes"), "client-go belongs to Kubernetes")
check(ss.upstream_for("github.com/unknown/zeta", registry) is None, "an unknown module has no upstream")
check(ss.upstream_for("GitHub.com/AndEnd-Collective/RunSecure/infra/telemetry", registry) is not None, "matching ignores case")

rows = ss.collect_vulnerabilities("infra/app", vdr, normal, registry)
check([r["id"] for r in rows] == ["CVE-2099-0001", "CVE-2023-44487"], "advisories are ordered by severity")
net = rows[1]
check(net["severity"] == "high", "the worst rating wins")
check(net["depth"] == 2 and net["path"] == ["example.test/app", "k8s.io/client-go@v1.0.0", "golang.org/x/net@v0.63.0"],
      "the import chain to the affected package is recorded")
check(net["upstream"].startswith("The Go project") and net["tracker"].startswith("https://"), "the fixing upstream is named")

stale = ss.apply_assessments(rows, assessments + [{"id": "CVE-0000-0000", "package": "example.test/gone", "verdict": "accepted", "reason": "r", "reference": "https://example.test"}])
check(rows[1]["assessment"]["verdict"] == "false_positive", "a reviewed assessment attaches to its match")
check(rows[0]["assessment"] is None, "an unreviewed match stays open")
check([a["id"] for a in stale] == ["CVE-0000-0000"], "an assessment that matches nothing is reported as stale")

status = ss.render_status({"infra/app": normal}, rows, registry, pins, "o/r", stale)
open_section = status.split("## Open advisories", 1)[1].split("## Assessed advisories", 1)[0]
assessed_section = status.split("## Assessed advisories", 1)[1].split("## Pinned components", 1)[0]
check("CVE-2099-0001" in open_section and "CVE-2023-44487" not in open_section, "only unassessed matches are listed as open")
check("CVE-2023-44487" in assessed_section and "**False positive.**" in assessed_section, "assessed matches stay visible with their verdict")
check("**not registered**" in open_section, "a match on an unregistered upstream says so")
check("| `infra/app` | 5 | 2 | 1 | 1 | 1 critical | 1 |" in status, "summary counts dependencies by distance and advisories by state")
check("no longer match anything" in status and "CVE-0000-0000" in status, "stale assessments are called out")
check("`github.com/unknown/zeta`" in status.split("## Upstreams not in the registry", 1)[1], "unregistered upstreams are listed")
check("RUNNER_VERSION=" in status, "pinned components show the current pin")

dependencies = ss.render_dependencies({"infra/app": normal}, registry)
check("| `golang.org/x/net@v0.63.0` | fourth party | k8s.io/client-go@v1.0.0 |" in dependencies, "dependency table shows what a fourth-party module is reached through")

# End to end through the CLI, twice: the output must not depend on the run.
for run in ("first", "second"):
    work = tmp / run
    (work / "sbom").mkdir(parents=True)
    (work / "vdr").mkdir()
    (work / "sbom" / "infra__app.cdx.json").write_text(json.dumps({**bom, "serialNumber": f"urn:uuid:{run}"}))
    (work / "vdr" / "infra__app.vdr.json").write_text(json.dumps(vdr))
    result = subprocess.run(
        [sys.executable, str(root / "infra/scripts/security-status.py"),
         "--sbom-dir", str(work / "sbom"), "--vdr-dir", str(work / "vdr"),
         "--upstreams", str(root / ".security/upstreams.yml"),
         "--assessments", str(root / ".security/assessments.yml"),
         "--repo-root", str(root), "--output-dir", str(work / "out"), "--repository", "o/r"],
        capture_output=True, text=True,
    )
    check(result.returncode == 0, f"generator failed: {result.stderr}")
files = sorted(p.relative_to(tmp / "first" / "out") for p in (tmp / "first" / "out").rglob("*") if p.is_file())
check([str(f) for f in files] == ["STATUS.md", "dependencies.md", "sbom/infra__app.cdx.json", "vulnerabilities.json"], f"generated set: {files}")
for name in files:
    check((tmp / "first" / "out" / name).read_bytes() == (tmp / "second" / "out" / name).read_bytes(), f"{name} differs between runs")

missing = tmp / "missing"
(missing / "sbom").mkdir(parents=True)
(missing / "vdr").mkdir()
(missing / "sbom" / "infra__app.cdx.json").write_text(json.dumps(bom))
result = subprocess.run(
    [sys.executable, str(root / "infra/scripts/security-status.py"),
     "--sbom-dir", str(missing / "sbom"), "--vdr-dir", str(missing / "vdr"),
     "--upstreams", str(root / ".security/upstreams.yml"), "--assessments", str(root / ".security/assessments.yml"),
     "--repo-root", str(root), "--output-dir", str(missing / "out"), "--repository", "o/r"],
    capture_output=True, text=True,
)
check(result.returncode != 0 and "no dep-scan report" in result.stderr, "a module without a dep-scan report is an error, not a clean result")

# ---- the committed status ----------------------------------------------------
committed = (root / ".security/STATUS.md").read_text()
check("no longer match anything" not in committed, "committed STATUS.md lists a stale assessment: remove it from assessments.yml")
for required in ("README.md", "STATUS.md", "dependencies.md", "vulnerabilities.json", "upstreams.yml", "assessments.yml"):
    check((root / ".security" / required).is_file(), f".security/{required} exists")
json.loads((root / ".security/vulnerabilities.json").read_text())

# ---- workflow trust boundaries ------------------------------------------------
workflow = yaml.safe_load((root / ".github/workflows/security-status.yml").read_text())
jobs = workflow["jobs"]
check(workflow["permissions"] == {}, "workflow grants nothing by default")
check(set(jobs) == {"scan", "pr", "merge"}, f"jobs: {sorted(jobs)}")
scan_text = json.dumps(jobs["scan"])
check(jobs["scan"]["permissions"] == {"contents": "read"}, "the scanning job can only read")
check("secrets." not in scan_text, "the job that runs third-party tools references no secret")
scan_checkout = next(s for s in jobs["scan"]["steps"] if "actions/checkout@" in s.get("uses", ""))
check(scan_checkout["with"]["persist-credentials"] is False, "the scanning job's checkout leaves no credential")
for name in ("pr", "merge"):
    text = json.dumps(jobs[name])
    check(not re.search(r"cdxgen|depscan|setup-go|npm install|pip install|generate-security-status", text),
          f"{name} holds a token and must not run the scanners")
    check("environment" not in jobs[name], f"{name}: no approval environment")
pr_run = next(s["run"] for s in jobs["pr"]["steps"] if s.get("id") == "open-pr")
check(pr_run.index("Status artifact rejected") < pr_run.index("git push origin"), "the artifact is validated before anything is pushed")
merge_run = next(s["run"] for s in jobs["merge"]["steps"] if "run" in s)
check(merge_run == 'bash infra/scripts/merge-pr-when-green.sh "$PR_URL" 4', "the refresh merges only through the green-checks gate")

print(f"PASS: upstream policy, status generator and workflow boundaries ({checks} checks)")
PY
