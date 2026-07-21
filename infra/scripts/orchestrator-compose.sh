#!/bin/bash
# Safe entrypoint for the persistent Compose orchestrator stack.
#
# Docker bind mounts dereference a host symlink before the mounted path is
# visible inside a container.  The pat-init service therefore cannot prove by
# itself that RUNSECURE_PAT_FILE names a non-symlink host file.  This wrapper
# validates the exact bind source rendered by Compose on the host, then exports
# the sentinel required by compose.scope.yml.  The sentinel prevents accidental
# direct `docker compose` launches from bypassing the supported preflight; it is
# not intended as a boundary against a malicious host operator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${RUNSECURE_ROOT}/infra/orchestrator/compose.scope.yml"
VALIDATION_SENTINEL="runsecure-host-pat-v1"

usage() {
    cat <<'EOF'
Usage: orchestrator-compose.sh --env-file PATH <compose-command> [args...]

Runs the tracked RunSecure orchestrator Compose stack. Commands that can
create or start services first require RUNSECURE_PAT_FILE to resolve to a
regular, non-symlink file owned by the invoking UID with mode exactly 0400.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi
if [[ ${1:-} != "--env-file" || -z ${2:-} || -z ${3:-} ]]; then
    usage >&2
    exit 2
fi

ENV_FILE=$2
shift 2
COMPOSE_COMMAND=$1

if [[ ! -f "$ENV_FILE" ]]; then
    echo "[RunSecure] ERROR: Compose env file is not a regular file: $ENV_FILE" >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "[RunSecure] ERROR: Docker Compose v2 ('docker compose') is required" >&2
    exit 1
fi
COMPOSE=(docker compose)

export RUNSECURE_PAT_HOST_VALIDATED="$VALIDATION_SENTINEL"
COMPOSE_BASE=("${COMPOSE[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE")

validate_host_pat() {
    "${COMPOSE_BASE[@]}" config --format json \
        | python3 "${SCRIPT_DIR}/validate-compose-pat.py" "$VALIDATION_SENTINEL"
}

# Teardown and read-only inspection must remain available if the PAT was
# intentionally removed or its permissions drifted.  Every command capable of
# creating or starting containers takes the validated path below.
case "$COMPOSE_COMMAND" in
    down|stop|kill|rm|logs|ps|events|top|images|port|version|help)
        ;;
    *)
        validate_host_pat
        ;;
esac

exec "${COMPOSE_BASE[@]}" "$@"
