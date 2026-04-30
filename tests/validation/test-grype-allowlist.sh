#!/bin/bash
# ============================================================================
# RunSecure — Grype Allowlist Hygiene
# ============================================================================
# Asserts .grype.yaml is well-formed AND every `vulnerability:` entry has
# an inline comment explaining the rationale.
#
# Without this, "fix the scan" becomes "add the GHSA to ignore:" and the
# allowlist quietly accumulates unjustified entries until it's effectively
# a scanner-disablement.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GRYPE_CFG="${RUNSECURE_ROOT}/.grype.yaml"

PASS=0
FAIL=0
RESULTS=()
pass() { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail() { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }

# --- File present + valid YAML ----------------------------------------------
if [[ ! -f "$GRYPE_CFG" ]]; then
    fail ".grype.yaml missing"
    echo "FAILED: 0/1"
    exit 1
fi
pass ".grype.yaml exists"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
    if python3 -c "import yaml,sys; yaml.safe_load(open('$GRYPE_CFG'))" 2>/dev/null; then
        pass ".grype.yaml is valid YAML"
    else
        fail ".grype.yaml fails YAML parse"
    fi
fi

# --- Each `vulnerability:` line has an inline `#` comment after it ----------
# Format we require: `  - vulnerability: GHSA-xxxx-xxxx-xxxx  # rationale`
unjustified=0
while IFS= read -r line; do
    # Skip blank lines, top-level comments
    if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+vulnerability: ]]; then
        # Must contain a #-comment after the GHSA/CVE id
        if [[ ! "$line" =~ \#[[:space:]]*[^[:space:]] ]]; then
            unjustified=$((unjustified + 1))
            fail "unjustified entry: $line"
        fi
    fi
done < "$GRYPE_CFG"
if [[ "$unjustified" -eq 0 ]]; then
    pass "every vulnerability entry has an inline justification comment"
fi

# --- Block-level rationale paragraphs present -------------------------------
# The file should explain WHY entries are accepted in a header comment.
if grep -qE 'Reachability:|RUNNER_VERSION|Re-evaluate' "$GRYPE_CFG"; then
    pass ".grype.yaml documents reachability + re-evaluation triggers"
else
    fail ".grype.yaml missing reachability / re-evaluation documentation"
fi

# --- Print results ----------------------------------------------------------
echo ""
echo "=== Grype Allowlist Hygiene ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed"
    exit 1
else
    echo "PASSED: $PASS tests"
    exit 0
fi
