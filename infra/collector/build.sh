#!/usr/bin/env bash
# No private checkout, token, generated source or binary is added to this repo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIN=490fc072c02d72a0dc62633d0c4f573b6707b4ef
OCB=v0.164.0
SOURCE="${CORNERSTONE_SOURCE:?Set CORNERSTONE_SOURCE to the separately authorized private checkout}"
OUT="${COLLECTOR_BUILD_DIR:?Set COLLECTOR_BUILD_DIR outside the public repository}"
OUT="$(python3 -c 'import pathlib,sys;print(pathlib.Path(sys.argv[1]).resolve())' "$OUT")"
SOURCE="$(cd "$SOURCE" && pwd -P)"
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$PIN" ]] || { echo 'Wrong Cornerstone source revision' >&2; exit 1; }
[[ -z "$(git -C "$SOURCE" status --porcelain)" ]] || { echo 'Cornerstone checkout must be clean' >&2; exit 1; }
[[ "$OUT" = /* && "$OUT" != "$ROOT" && "$OUT" != "$ROOT/"* ]] || { echo 'Build directory must be absolute and outside public repository' >&2; exit 1; }
if [[ "${BUILD_IMAGE:-0}" == 1 ]]; then
  : "${COLLECTOR_GATEWAY_IMAGE:?Set a local-only gateway image tag}"
  : "${COLLECTOR_NODE_IMAGE:?Set a different local-only node image tag}"
  [[ "$COLLECTOR_GATEWAY_IMAGE" != "$COLLECTOR_NODE_IMAGE" ]] || { echo 'Role image tags must be distinct' >&2; exit 1; }
  [[ -z "${COLLECTOR_IMAGE:-}" ]] || { echo 'COLLECTOR_IMAGE is retired; set both role image tags' >&2; exit 1; }
fi
mkdir -p "$OUT/bin"
cp "$ROOT/infra/collector/builder-config.yaml" "$OUT/builder-config.yaml"
ln -sfn "$SOURCE" "$OUT/cornerstone-src"
ln -sfn "$ROOT/infra/collector/processor" "$OUT/public-processor"
GOBIN="$OUT/bin" go install "go.opentelemetry.io/collector/cmd/builder@$OCB"
[[ "$("$OUT/bin/builder" version 2>&1)" == "ocb version $OCB" ]] || { echo 'OCB version mismatch' >&2; exit 1; }
(cd "$OUT" && CGO_ENABLED=0 "$OUT/bin/builder" --skip-strict-versioning=false --config=builder-config.yaml)
go version -m "$OUT/dist/runsecure-collector" > "$OUT/build-info.txt"
echo "Built $OUT/dist/runsecure-collector with $OCB; inspect build-info.txt for resolved modules"
if [[ "${BUILD_IMAGE:-0}" == 1 ]]; then
  for target in gateway node; do
    if [[ "$target" == gateway ]]; then image="$COLLECTOR_GATEWAY_IMAGE"; else image="$COLLECTOR_NODE_IMAGE"; fi
    docker build --file "$ROOT/infra/collector/Dockerfile" --target "$target" \
      --build-context "cornerstone-src=$SOURCE/otel-collector" \
      --label "runsecure.io/cornerstone-source=$PIN" \
      --label "runsecure.io/collector-role=$target" \
      --tag "$image" "$ROOT"
  done
fi
