#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT DIGEST_FILE..." >&2
  exit 2
}

if (( $# < 2 )); then
  usage
fi

output=$1
shift

tmp=$(mktemp "${TMPDIR:-/tmp}/runsecure-release-allowlist.XXXXXX")
trap 'rm -f "$tmp"' EXIT

have_proxy=false
have_node=false
have_python=false
have_rust=false

for digest_file in "$@"; do
  if [[ ! -f "$digest_file" ]]; then
    echo "missing digest file: $digest_file" >&2
    exit 1
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue

    if [[ ! "$line" =~ ^ghcr\.io/andend-collective/runsecure/(proxy|node|python|rust)@sha256:[0-9a-f]{64}$ ]]; then
      echo "invalid release image digest in $digest_file: $line" >&2
      exit 1
    fi

    package=${BASH_REMATCH[1]}
    case "$package" in
      proxy) have_proxy=true ;;
      node) have_node=true ;;
      python) have_python=true ;;
      rust) have_rust=true ;;
    esac
    printf '%s\n' "$line" >> "$tmp"
  done < "$digest_file"
done

missing=()
for package in proxy node python rust; do
  case "$package" in
    proxy) present=$have_proxy ;;
    node) present=$have_node ;;
    python) present=$have_python ;;
    rust) present=$have_rust ;;
  esac
  if [[ "$present" != true ]]; then
    missing+=("$package")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "release allowlist is missing required package digests: ${missing[*]}" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output")"
{
  echo "# Generated from immutable build outputs by publish-images.yml."
  echo "# Package names are the real GHCR packages: proxy, node, python, rust."
  LC_ALL=C sort -u "$tmp"
} > "$output"
