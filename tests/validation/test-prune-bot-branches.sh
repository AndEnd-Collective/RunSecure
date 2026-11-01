#!/usr/bin/env bash
# prune-bot-branches.sh deletes superseded bot branches from origin. It keeps
# the current branch and any branch with an open PR, refuses prefixes outside
# bot/, and deletes nothing when the open-PR lookup fails.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/infra/scripts/prune-bot-branches.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

workflow_call="run: bash infra/scripts/prune-bot-branches.sh bot/go-deps- \"bot/go-deps-\${NEXT_VERSION}\""
grep -Fq "$workflow_call" "$ROOT/.github/workflows/weekly-version-bump.yml" \
  || fail "weekly-version-bump.yml must prune superseded bot/go-deps- branches"

git init -q --bare "$WORK/origin.git"
git init -q "$WORK/clone"
cd "$WORK/clone"
git -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m seed
git remote add origin "$WORK/origin.git"
for branch in main bot/go-deps-v1 bot/go-deps-v2 bot/go-deps-v3 bot/allowed-images-v1; do
  git push -q origin "HEAD:refs/heads/$branch"
done

# gh stub: bot/go-deps-v1 has an open PR; GH_STUB_FAIL makes every lookup fail.
mkdir "$WORK/bin"
cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ -z "${GH_STUB_FAIL:-}" ]] || { echo "gh: HTTP 502" >&2; exit 1; }
head=""
while [[ $# -gt 0 ]]; do
  [[ "$1" == --head ]] && head="$2"
  shift
done
[[ "$head" == bot/go-deps-v1 ]] && echo 1 || echo 0
STUB
chmod +x "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"

remaining() { git ls-remote --heads origin | awk '{sub("refs/heads/", "", $2); print $2}' | sort | tr '\n' ' '; }

GH_STUB_FAIL=1 bash "$SCRIPT" bot/go-deps- bot/go-deps-v3 >/dev/null 2>&1 \
  && fail "a failed open-PR lookup must fail the prune"
[[ "$(remaining)" == "bot/allowed-images-v1 bot/go-deps-v1 bot/go-deps-v2 bot/go-deps-v3 main " ]] \
  || fail "a failed open-PR lookup deleted branches: $(remaining)"

for prefix in "" main bot/ bot-go-deps-; do
  bash "$SCRIPT" "$prefix" bot/go-deps-v3 >/dev/null 2>&1 && fail "prefix '$prefix' must be refused"
done

bash "$SCRIPT" bot/go-deps- bot/go-deps-v3 >/dev/null
[[ "$(remaining)" == "bot/allowed-images-v1 bot/go-deps-v1 bot/go-deps-v3 main " ]] \
  || fail "expected only bot/go-deps-v2 pruned, got: $(remaining)"

bash "$SCRIPT" bot/go-deps- bot/go-deps-v3 >/dev/null || fail "a second run must be a no-op"
[[ "$(remaining)" == "bot/allowed-images-v1 bot/go-deps-v1 bot/go-deps-v3 main " ]] \
  || fail "second run changed branches: $(remaining)"

echo "PASS: superseded bot branches pruned; current, open-PR and other-prefix branches kept; lookup failure deletes nothing"
