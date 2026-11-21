#!/bin/bash
# ============================================================================
# RunSecure — regenerate .security/ from an OWASP dep-scan run
# ============================================================================
# For every Go module in the repository:
#   1. cdxgen writes a CycloneDX SBOM, including the dependency graph that
#      shows how far each module is from our own code;
#   2. OWASP dep-scan matches that SBOM against its vulnerability database
#      and writes a CycloneDX VDR.
# infra/scripts/security-status.py then turns the SBOMs, the VDRs and
# .security/upstreams.yml into the published files under .security/.
#
# The tools run on an exported copy of HEAD, never in the working tree:
# cdxgen writes scratch files next to what it scans.
#
# Usage: generate-security-status.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to <repo>/.security
#
# Requires on PATH: cdxgen, depscan, go, jq, git, python3 (with PyYAML).
# The dep-scan application database (about 4.5 GB) is downloaded on first use.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${1:-${RUNSECURE_ROOT}/.security}"
REPOSITORY="${GITHUB_REPOSITORY:-AndEnd-Collective/RunSecure}"

for tool in cdxgen depscan go jq git python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: ${tool} is required" >&2
        exit 1
    }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-security-status-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src" "$WORK/sbom" "$WORK/vdr" "$WORK/reports"

git -C "$RUNSECURE_ROOT" archive HEAD | tar -x -C "$WORK/src"

modules=()
while IFS= read -r gomod; do
    modules+=("$(dirname "$gomod")")
done < <(git -C "$RUNSECURE_ROOT" ls-files '*go.mod' | sort)
if [[ ${#modules[@]} -eq 0 ]]; then
    echo "ERROR: no Go modules found" >&2
    exit 1
fi

for module in "${modules[@]}"; do
    slug="${module//\//__}"
    echo "=== ${module}"
    (
        cd "$WORK/src/$module"
        cdxgen -t go --deep -o "$WORK/sbom/${slug}.cdx.json" . > "$WORK/reports/${slug}.cdxgen.log" 2>&1
    ) || {
        echo "ERROR: cdxgen failed for ${module}:" >&2
        tail -20 "$WORK/reports/${slug}.cdxgen.log" >&2
        exit 1
    }
    if ! jq -e '.bomFormat == "CycloneDX"' "$WORK/sbom/${slug}.cdx.json" >/dev/null 2>&1; then
        echo "ERROR: cdxgen wrote no SBOM for ${module}" >&2
        exit 1
    fi

    # A module made only of tests compiles no third-party package into
    # anything we ship, so cdxgen lists no components and there is nothing
    # for dep-scan to match. Its go.mod is still watched by Dependabot.
    if [[ "$(jq '.components | length' "$WORK/sbom/${slug}.cdx.json")" == "0" ]]; then
        echo '{"vulnerabilities": []}' > "$WORK/vdr/${slug}.vdr.json"
        echo "    components: 0 (nothing built from third-party code)"
        continue
    fi

    mkdir -p "$WORK/reports/$slug"
    depscan --bom "$WORK/sbom/${slug}.cdx.json" \
        --reports-dir "$WORK/reports/$slug" \
        --vdb-scope app --no-banner --no-vuln-table \
        > "$WORK/reports/${slug}.depscan.log" 2>&1 || {
        echo "ERROR: dep-scan failed for ${module}:" >&2
        tail -20 "$WORK/reports/${slug}.depscan.log" >&2
        exit 1
    }
    # dep-scan names its VDR after the SBOM file, and writes none at all when
    # nothing matched. "No report" is accepted as "no vulnerabilities" only
    # when dep-scan itself said so; otherwise a scan that silently produced
    # nothing would read as a clean result.
    reports=()
    while IFS= read -r report; do
        reports+=("$report")
    done < <(find "$WORK/reports/$slug" -maxdepth 1 -name '*.vdr.json' | sort)
    if [[ ${#reports[@]} -eq 1 ]]; then
        cp "${reports[0]}" "$WORK/vdr/${slug}.vdr.json"
    elif [[ ${#reports[@]} -eq 0 ]] && grep -q 'No vulnerabilities found' "$WORK/reports/${slug}.depscan.log"; then
        echo '{"vulnerabilities": []}' > "$WORK/vdr/${slug}.vdr.json"
    else
        echo "ERROR: dep-scan wrote ${#reports[@]} vulnerability reports for ${module} and did not report a clean scan" >&2
        tail -20 "$WORK/reports/${slug}.depscan.log" >&2
        exit 1
    fi
    echo "    components: $(jq '.components | length' "$WORK/sbom/${slug}.cdx.json")," \
        "advisories: $(jq '.vulnerabilities | length' "$WORK/vdr/${slug}.vdr.json")"
done

python3 "${SCRIPT_DIR}/security-status.py" \
    --sbom-dir "$WORK/sbom" \
    --vdr-dir "$WORK/vdr" \
    --upstreams "${RUNSECURE_ROOT}/.security/upstreams.yml" \
    --assessments "${RUNSECURE_ROOT}/.security/assessments.yml" \
    --repo-root "$RUNSECURE_ROOT" \
    --output-dir "$OUTPUT_DIR" \
    --repository "$REPOSITORY"

echo "Wrote ${OUTPUT_DIR}/STATUS.md, dependencies.md, vulnerabilities.json and sbom/."
