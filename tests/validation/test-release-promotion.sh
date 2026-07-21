#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROMOTER="${RUNSECURE_ROOT}/infra/scripts/promote-release-images.py"
README="${RUNSECURE_ROOT}/README.md"

if grep -Fq '| **Floating minor**' "$README" \
    || grep -Fq '`python:1.1-3.12`' "$README" \
    || grep -Fq '`:1.1`' "$README"; then
    echo "FAIL: README promises floating-minor tags that promotion does not publish" >&2
    exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/runsecure-promotion-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "${tmp}/bin"

cat > "${tmp}/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$PROMOTION_DOCKER_LOG"

lookup() {
    local reference=$1
    local value
    value=$(awk -F '\t' -v ref="$reference" '$1 == ref { value=$2 } END { print value }' \
        "$PROMOTION_MAP" "$PROMOTION_STATE")
    if [[ -n "$value" ]]; then
        printf '%s\n' "$value"
        return 0
    fi
    if [[ "$reference" =~ @((sha256:)[0-9a-f]{64})$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

if [[ "$1 $2 $3" == "buildx imagetools inspect" ]]; then
    reference=$4
    if [[ "${PROMOTION_DENY_REF:-}" == "$reference" ]]; then
        echo "unauthorized: simulated registry dependency failure" >&2
        exit 1
    fi
    if lookup "$reference"; then
        exit 0
    fi
    echo "manifest unknown: $reference not found" >&2
    exit 1
fi

if [[ "$1 $2 $3 $4" == "buildx imagetools create --tag" ]]; then
    target=$5
    source=$6
    if ! digest=$(lookup "$source"); then
        echo "source missing: $source" >&2
        exit 1
    fi
    if [[ "${PROMOTION_FAIL_TARGET:-}" == "$target" \
        && ! -e "${PROMOTION_FAIL_MARKER:-/nonexistent}" ]]; then
        [[ -z "${PROMOTION_FAIL_MARKER:-}" ]] || touch "$PROMOTION_FAIL_MARKER"
        echo "simulated tag write failure: $target" >&2
        exit 1
    fi
    printf '%s\t%s\n' "$target" "$digest" >> "$PROMOTION_STATE"
    if [[ "${PROMOTION_FAIL_AFTER_WRITE_TARGET:-}" == "$target" \
        && ! -e "${PROMOTION_FAIL_MARKER:-/nonexistent}" ]]; then
        [[ -z "${PROMOTION_FAIL_MARKER:-}" ]] || touch "$PROMOTION_FAIL_MARKER"
        echo "simulated response failure after tag write: $target" >&2
        exit 1
    fi
    exit 0
fi

echo "unexpected mock docker invocation: $*" >&2
exit 2
MOCK
chmod +x "${tmp}/bin/docker"

python3 - "$PROMOTER" "$tmp" <<'PY'
import importlib.util
import json
import pathlib
import sys

script = pathlib.Path(sys.argv[1])
tmp = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("runsecure_promoter", script)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

release = "2.1.8"
images = {}
mapping = []
stable_refs = []
aliases = []
for index, promotion in enumerate(module.PROMOTIONS, start=1):
    digest = f"sha256:{index:064x}"
    package_ref = f"{module.IMAGE_PREFIX}/{promotion.package}"
    source = f"{package_ref}@{digest}"
    canary = f"{package_ref}:{release}-canary{promotion.canary_suffix}"
    stable = f"{package_ref}:{release}{promotion.stable_suffix}"
    images[promotion.manifest_key] = source
    mapping.extend(((source, digest), (canary, digest)))
    stable_refs.append((stable, digest))
    aliases.append((f"{package_ref}:{promotion.alias}", f"sha256:{index + 100:064x}"))

manifest = {
    "schema_version": 2,
    "release": release,
    "build_sha": "1" * 40,
    "publish_run_id": 123456,
    "images": images,
}
(tmp / "release-images.json").write_text(json.dumps(manifest) + "\n")
(tmp / "mapping.tsv").write_text(
    "".join(f"{reference}\t{digest}\n" for reference, digest in mapping)
)
(tmp / "stable.tsv").write_text(
    "".join(f"{reference}\t{digest}\n" for reference, digest in stable_refs)
)
(tmp / "aliases.tsv").write_text(
    "".join(f"{reference}\t{digest}\n" for reference, digest in aliases)
)
PY

export PATH="${tmp}/bin:${PATH}"
export PROMOTION_DOCKER_LOG="${tmp}/docker.log"
export PROMOTION_MAP="${tmp}/mapping.tsv"
export PROMOTION_STATE="${tmp}/state.tsv"
touch "$PROMOTION_DOCKER_LOG" "$PROMOTION_STATE"

# A conflict found at the end of the aggregate preflight must prevent every
# version and alias mutation. All sources and all version destinations must
# still have been inspected before the script returns.
tail -n 1 "${tmp}/stable.tsv" >> "$PROMOTION_MAP"
sed -i.bak '$s/sha256:[0-9a-f]*/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' \
    "$PROMOTION_MAP"
if python3 "$PROMOTER" "${tmp}/release-images.json" --release 2.1.8 \
    >"${tmp}/conflict.out" 2>"${tmp}/conflict.err"; then
    echo "FAIL: promotion accepted a conflicting immutable version tag" >&2
    exit 1
fi
if grep -q 'imagetools create' "$PROMOTION_DOCKER_LOG"; then
    echo "FAIL: promotion mutated a tag before aggregate preflight passed" >&2
    exit 1
fi
if [[ $(grep -c 'imagetools inspect .*@sha256:' "$PROMOTION_DOCKER_LOG") -ne 12 ]]; then
    echo "FAIL: aggregate preflight did not inspect all 12 immutable sources" >&2
    exit 1
fi
while IFS=$'\t' read -r reference _digest; do
    if ! grep -Fq "imagetools inspect ${reference} " "$PROMOTION_DOCKER_LOG"; then
        echo "FAIL: aggregate preflight skipped version destination $reference" >&2
        exit 1
    fi
done < "${tmp}/stable.tsv"

# An unclassified dependency error is not equivalent to an absent tag.
head -n 1 "${tmp}/stable.tsv" | cut -f1 > "${tmp}/denied-ref"
sed '$d' "${tmp}/mapping.tsv" > "${tmp}/mapping.clean.tsv"
mv "${tmp}/mapping.clean.tsv" "$PROMOTION_MAP"
: > "$PROMOTION_DOCKER_LOG"
: > "$PROMOTION_STATE"
export PROMOTION_DENY_REF
PROMOTION_DENY_REF=$(cat "${tmp}/denied-ref")
if python3 "$PROMOTER" "${tmp}/release-images.json" --release 2.1.8 \
    >"${tmp}/denied.out" 2>"${tmp}/denied.err"; then
    echo "FAIL: promotion treated a registry authorization failure as tag absence" >&2
    exit 1
fi
if grep -q 'imagetools create' "$PROMOTION_DOCKER_LOG"; then
    echo "FAIL: promotion mutated a tag after an unclassified preflight error" >&2
    exit 1
fi
unset PROMOTION_DENY_REF

# On success, all 48 read-only source/canary/version/alias inspections happen
# before the first create. All version tags are then created and verified before
# any floating alias moves.
python3 - "$PROMOTION_MAP" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
lines = [line for line in path.read_text().splitlines() if "@sha256:" in line or "-canary" in line]
path.write_text("\n".join(lines) + "\n")
PY
: > "$PROMOTION_DOCKER_LOG"
: > "$PROMOTION_STATE"
python3 "$PROMOTER" "${tmp}/release-images.json" --release 2.1.8

first_create=$(grep -n 'imagetools create' "$PROMOTION_DOCKER_LOG" | head -n 1 | cut -d: -f1)
inspects_before=$(head -n "$((first_create - 1))" "$PROMOTION_DOCKER_LOG" \
    | grep -c 'imagetools inspect')
if [[ "$inspects_before" -ne 48 ]]; then
    echo "FAIL: first mutation occurred before all 48 aggregate preflight reads" >&2
    exit 1
fi
first_alias_create=$(grep -nE 'imagetools create --tag .*:latest' \
    "$PROMOTION_DOCKER_LOG" | head -n 1 | cut -d: -f1)
version_creates_before=$(head -n "$((first_alias_create - 1))" "$PROMOTION_DOCKER_LOG" \
    | grep -c 'imagetools create')
if [[ "$version_creates_before" -ne 12 ]]; then
    echo "FAIL: floating alias moved before all 12 version tags were created" >&2
    exit 1
fi
if [[ $(grep -c 'imagetools create' "$PROMOTION_DOCKER_LOG") -ne 24 ]]; then
    echo "FAIL: successful promotion did not create 12 version and 12 alias tags" >&2
    exit 1
fi

# If a registry reports failure after writing an alias, restore every attempted
# alias to its captured pre-promotion digest. This includes the ambiguous alias
# whose write returned an error.
cat "${tmp}/aliases.tsv" >> "$PROMOTION_MAP"
: > "$PROMOTION_DOCKER_LOG"
: > "$PROMOTION_STATE"
export PROMOTION_FAIL_AFTER_WRITE_TARGET
export PROMOTION_FAIL_MARKER="${tmp}/rollback-failed-once"
rm -f "$PROMOTION_FAIL_MARKER"
PROMOTION_FAIL_AFTER_WRITE_TARGET=$(sed -n '5p' "${tmp}/aliases.tsv" | cut -f1)
if python3 "$PROMOTER" "${tmp}/release-images.json" --release 2.1.8 \
    >"${tmp}/rollback.out" 2>"${tmp}/rollback.err"; then
    echo "FAIL: simulated alias write failure unexpectedly succeeded" >&2
    exit 1
fi
unset PROMOTION_FAIL_AFTER_WRITE_TARGET
unset PROMOTION_FAIL_MARKER
if ! grep -q 'changed aliases were restored' "${tmp}/rollback.err"; then
    echo "FAIL: promotion did not report successful alias rollback" >&2
    cat "${tmp}/rollback.err" >&2
    exit 1
fi
while IFS=$'\t' read -r reference expected; do
    actual=$(awk -F '\t' -v ref="$reference" \
        '$1 == ref { value=$2 } END { print value }' \
        "$PROMOTION_MAP" "$PROMOTION_STATE")
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: alias rollback left $reference at $actual (expected $expected)" >&2
        exit 1
    fi
done < "${tmp}/aliases.tsv"

# buildx cannot safely delete only a newly-created tag: deleting by manifest
# digest could remove other references. Surface that residual explicitly when
# an absent alias is written and the registry then reports failure.
sed '/:latest/d' "$PROMOTION_MAP" > "${tmp}/mapping.no-aliases.tsv"
mv "${tmp}/mapping.no-aliases.tsv" "$PROMOTION_MAP"
: > "$PROMOTION_DOCKER_LOG"
: > "$PROMOTION_STATE"
export PROMOTION_FAIL_AFTER_WRITE_TARGET
export PROMOTION_FAIL_MARKER="${tmp}/residual-failed-once"
rm -f "$PROMOTION_FAIL_MARKER"
PROMOTION_FAIL_AFTER_WRITE_TARGET=$(head -n 1 "${tmp}/aliases.tsv" | cut -f1)
if python3 "$PROMOTER" "${tmp}/release-images.json" --release 2.1.8 \
    >"${tmp}/residual.out" 2>"${tmp}/residual.err"; then
    echo "FAIL: newly-created alias response failure unexpectedly succeeded" >&2
    exit 1
fi
unset PROMOTION_FAIL_AFTER_WRITE_TARGET
unset PROMOTION_FAIL_MARKER
if ! grep -q 'newly created alias cannot be safely deleted' "${tmp}/residual.err"; then
    echo "FAIL: unsafe tag-only deletion boundary was not reported" >&2
    cat "${tmp}/residual.err" >&2
    exit 1
fi

echo "PASS: release promotion preflights all images and fails closed before mutation"
