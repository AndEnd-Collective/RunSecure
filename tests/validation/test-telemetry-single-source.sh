#!/usr/bin/env bash
# Telemetry has exactly one source (infra/telemetry). Every consumer module
# replaces it by relative path, and every image build of a consumer passes it
# as the `telemetry` named build context so each image's main context stays
# scoped to its own module. Static checks only: the hardened dogfood runner has
# no Go toolchain or Docker; the compose integration suite builds both images
# through _lib.sh with the named context on hosted runners.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
MODULE=github.com/AndEnd-Collective/runsecure/infra/telemetry
fail() { echo "FAIL: $*" >&2; exit 1; }

copies="$(find infra -type d -path '*/internal/telemetry')"
[[ -z "$copies" ]] || fail "mirrored telemetry copies remain: $copies"

importers="$(grep -rl --include='*.go' 'internal/telemetry"' infra || true)"
[[ -z "$importers" ]] || fail "imports of a module-local telemetry copy: $importers"

for entry in infra/orchestrator:../telemetry infra/socket-proxy:../telemetry infra/collector/processor:../../telemetry; do
  dir="${entry%%:*}"
  want="${entry#*:}"
  got="$(sed -n -E "s#^replace ${MODULE} => ([^ ]+)\$#\\1#p" "$dir/go.mod")"
  [[ "$got" == "$want" ]] || fail "$dir/go.mod must replace $MODULE => $want (got '${got}')"
done

# The OCB-generated distribution is the main module of the collector build, so
# the processor's own replace does not apply there; builder-config must carry it.
grep -qE "^  - ${MODULE} => \.\./telemetry\$" infra/collector/builder-config.yaml \
  || fail "infra/collector/builder-config.yaml must replace $MODULE => ../telemetry"

# Every build of the orchestrator/socket-proxy Dockerfiles must pass the
# named context, otherwise `COPY --from=telemetry` resolves to a registry image.
missing=""
while IFS= read -r site; do
  file="${site%%:*}"
  line="${site#*:}"; line="${line%%:*}"
  window="$(sed -n "$((line - 4)),$((line + 6))p" "$file")"
  grep -q 'telemetry=' <<<"$window" || missing+=" ${file}:${line}"
done < <(grep -rn -E 'infra/(orchestrator|socket-proxy)/Dockerfile' .github/workflows tests infra/scripts \
  --include='*.yml' --include='*.yaml' --include='*.sh' | grep -v 'test-telemetry-single-source.sh')
[[ -z "$missing" ]] || fail "image builds without the telemetry named context:$missing"

echo "PASS: telemetry has one source; all consumers and image builds resolve it"
