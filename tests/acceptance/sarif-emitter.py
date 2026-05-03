#!/usr/bin/env python3
"""
RunSecure — SARIF v2.1.0 emitter for acceptance test results.

Reads PASS:/FAIL:/SKIP: lines from stdin (the format produced by
tests/acceptance/in-container/lib.sh) and emits a SARIF v2.1.0 JSON
document on stdout. Each acceptance check is a SARIF rule defined in
tests/acceptance/claims.yml; each FAIL becomes a SARIF result that
GitHub Code Scanning surfaces in the Security tab.

Usage:
    python3 sarif-emitter.py \\
        --claims tests/acceptance/claims.yml \\
        --image-ref ghcr.io/andend-collective/runsecure/node:1.2.3-beta-24 \\
        --commit-sha abc123 \\
        < acceptance-output.txt > acceptance.sarif

Exit code: always 0 (the SARIF is the report — gating is the workflow's job).

Output contract:
    Each PASS/FAIL/SKIP line:    PASS: <claim_id> <description>
    SKIP includes a reason:      SKIP: <claim_id> <description> — <reason>
    Anything else is ignored (group markers, separators, etc).
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with `pip install pyyaml`.", file=sys.stderr)
    sys.exit(1)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "RunSecure Acceptance Suite"
TOOL_INFO_URI = "https://github.com/AndEnd-Collective/RunSecure"
SECURITY_MD_BASE_URI = "https://github.com/AndEnd-Collective/RunSecure/blob/main/SECURITY.md"

# Match: PASS: H01 description...   /   FAIL: R02 description...   /   SKIP: N03 desc — reason
LINE_RE = re.compile(r"^(PASS|FAIL|SKIP):\s+([HRN]\d{2})\s+(.*?)(?:\s+—\s+(.*))?$")


def load_claims(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def severity_to_sarif_level(severity: str) -> str:
    """Map our severity vocabulary to SARIF levels."""
    return {"error": "error", "warning": "warning", "note": "note"}.get(severity, "error")


def parse_results(stream) -> list:
    """Parse PASS/FAIL/SKIP lines into structured results."""
    results = []
    for raw in stream:
        line = raw.rstrip("\n").rstrip("\r")
        m = LINE_RE.match(line)
        if not m:
            continue
        kind, claim_id, desc, skip_reason = m.groups()
        results.append({
            "kind": kind,
            "claim": claim_id,
            "description": desc.strip(),
            "skip_reason": skip_reason.strip() if skip_reason else None,
        })
    return results


def build_rule(claim_id: str, claim: dict) -> dict:
    """Build a SARIF rule definition from a claim catalog entry."""
    help_uri = f"{SECURITY_MD_BASE_URI}#{claim['section']}"
    return {
        "id": claim_id,
        "name": claim_id,
        "shortDescription": {"text": claim["short"]},
        "fullDescription":  {"text": claim["full"]},
        "helpUri": help_uri,
        "help": {
            "text": claim["full"],
            "markdown": (
                f"### Acceptance claim {claim_id}: {claim['short']}\n\n"
                f"{claim['full']}\n\n"
                f"**Severity:** {claim['severity']}  \n"
                f"**Documented in:** [SECURITY.md#{claim['section']}]({help_uri})\n\n"
                f"If this finding appears, the published image does not deliver on a documented "
                f"security claim. See the [README "
                f"troubleshooting]({TOOL_INFO_URI}#operational-notes) for next steps."
            ),
        },
        "defaultConfiguration": {"level": severity_to_sarif_level(claim["severity"])},
        "properties": {
            "tags": claim.get("tags", []) + ["security", "runsecure-acceptance"],
            "precision": "very-high",
            "security-severity": "9.0" if claim["severity"] == "error" else "5.0",
        },
    }


def build_result(parsed: dict, claim: dict, image_ref: str, commit_sha: str) -> dict:
    """Build a SARIF result for one FAIL line."""
    cid = parsed["claim"]
    location_uri = f"SECURITY.md#{claim['section']}"
    msg = (
        f"Acceptance claim {cid} FAILED for {image_ref}: {parsed['description']}. "
        f"The published image did not deliver on the documented security property. "
        f"See SECURITY.md for the claim text and README \"Operational notes\" for "
        f"next-step guidance."
    )
    return {
        "ruleId": cid,
        "ruleIndex": 0,  # backfilled by caller
        "level": severity_to_sarif_level(claim["severity"]),
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "SECURITY.md",
                    "uriBaseId": "%SRCROOT%",
                },
                # SARIF requires region; reference the section header line as a
                # placeholder. GitHub Code Scanning shows the file + region.
                "region": {"startLine": 1},
            },
        }],
        # partialFingerprints — GitHub uses these for cross-run dedup.
        # Same image-ref + same claim ID = same finding across runs.
        "partialFingerprints": {
            "claim/v1": cid,
            "image-ref/v1": image_ref,
        },
        "properties": {
            "image-ref": image_ref,
            "commit-sha": commit_sha,
            "claim-description": parsed["description"],
        },
    }


def build_sarif(parsed_lines: list, claims: dict, image_ref: str, commit_sha: str) -> dict:
    """Assemble the SARIF document."""
    # Build rules in the order claims appear in the catalog so the rules array
    # is stable across runs (helpful for diffing SARIF output).
    rule_ids = list(claims.keys())
    rules = [build_rule(cid, claims[cid]) for cid in rule_ids]
    rule_index_for = {cid: i for i, cid in enumerate(rule_ids)}

    results = []
    seen_unknown_claims = set()
    for parsed in parsed_lines:
        if parsed["kind"] != "FAIL":
            continue
        cid = parsed["claim"]
        if cid not in claims:
            if cid not in seen_unknown_claims:
                print(f"WARN: claim {cid} not found in claims.yml — emitting result without rule",
                      file=sys.stderr)
                seen_unknown_claims.add(cid)
            continue
        result = build_result(parsed, claims[cid], image_ref, commit_sha)
        result["ruleIndex"] = rule_index_for[cid]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": TOOL_INFO_URI,
                    "version": "1.0.0",
                    "rules": rules,
                },
            },
            "results": results,
            "properties": {
                "image-ref": image_ref,
                "commit-sha": commit_sha,
                "total-checks": len(parsed_lines),
                "passes": sum(1 for p in parsed_lines if p["kind"] == "PASS"),
                "failures": sum(1 for p in parsed_lines if p["kind"] == "FAIL"),
                "skips": sum(1 for p in parsed_lines if p["kind"] == "SKIP"),
            },
        }],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    p.add_argument("--claims", required=True, type=Path,
                   help="Path to claims.yml (catalog of every acceptance claim ID)")
    p.add_argument("--image-ref", default="(unspecified)",
                   help="The published image being tested (e.g. ghcr.io/.../node:1.2.3-beta-24)")
    p.add_argument("--commit-sha", default="(unspecified)",
                   help="Git commit SHA the acceptance run was for")
    p.add_argument("--output", "-o", type=Path, default=None,
                   help="Write SARIF here (default: stdout)")
    args = p.parse_args()

    if not args.claims.exists():
        print(f"ERROR: claims file not found: {args.claims}", file=sys.stderr)
        sys.exit(2)

    claims = load_claims(args.claims)
    parsed_lines = parse_results(sys.stdin)
    sarif = build_sarif(parsed_lines, claims, args.image_ref, args.commit_sha)

    out = args.output.open("w") if args.output else sys.stdout
    json.dump(sarif, out, indent=2)
    if args.output:
        out.close()

    n_fail = sarif["runs"][0]["properties"]["failures"]
    n_total = sarif["runs"][0]["properties"]["total-checks"]
    print(f"sarif-emitter: {n_fail} failures of {n_total} checks → {args.output or 'stdout'}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
