#!/usr/bin/env bash
# Verify the orchestrator refuses to start with a PAT file that isn't 0400.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

PAT="$WORKDIR/pat"
echo "ghp_test" > "$PAT"
chmod 644 "$PAT" # WRONG — must be 0400

mkdir -p "$WORKDIR/proj/.github"
echo "runtime: node:24" > "$WORKDIR/proj/.github/runner.yml"

cat > "$WORKDIR/scope.yml" <<EOF
apiVersion: runsecure.io/v1alpha1
name: test
global_max_runners: 1
poll_interval_seconds: 15
security_profile: strict
auth:
  type: pat
  pat_file: /pat
orch_egress:
  allow_domains: [api.github.com]
repos:
  - repo: o/r
    project_dir: /proj
    max_concurrent: 1
EOF

OUT=$(docker run --rm \
  -v "$PAT:/pat:ro" \
  -v "$WORKDIR/scope.yml:/etc/runsecure/scope.yml:ro" \
  -v "$WORKDIR/proj:/proj:ro" \
  -e RUNSECURE_SCOPE_FILE=/etc/runsecure/scope.yml \
  runsecure-orchestrator:local 2>&1 || true)

if echo "$OUT" | grep -qi "mode 0400"; then
  echo "PASS: orchestrator refused PAT with wrong mode"
else
  echo "FAIL: unexpected output: $OUT"
  exit 1
fi
