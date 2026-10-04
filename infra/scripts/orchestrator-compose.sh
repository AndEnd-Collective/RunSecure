#!/bin/bash
# Safe entrypoint for the persistent Compose orchestrator stack.
#
# Docker bind mounts dereference a host symlink before the mounted path is
# visible inside a container.  The auth-secret-init service therefore cannot
# prove by itself that the credential bind names a non-symlink host file.  This
# wrapper validates the exact bind source rendered by Compose on the host, then
# exports the sentinel required by compose.scope.yml.  The sentinel prevents
# accidental direct `docker compose` launches from bypassing the supported
# preflight; it is not intended as a boundary against a malicious host operator.
#
# The stack supports two credential types and selects the init path from
# auth.type in the scope YAML (issue #64 — a github_app scope used to be
# forced to supply an unrelated PAT):
#
#   auth.type: pat         host file RUNSECURE_PAT_FILE
#                          -> /run/secrets/runsecure-pat
#   auth.type: github_app  host file RUNSECURE_APP_PRIVATE_KEY_FILE
#                          -> /run/secrets/runsecure-app-private-key
#
# Both are delivered by the same one-shot init through the same named volume,
# and both must be regular, non-symlink files owned by the invoking UID with
# mode exactly 0400.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${RUNSECURE_ROOT}/infra/orchestrator/compose.scope.yml"
VALIDATION_SENTINEL="runsecure-host-auth-secret-v1"

usage() {
    cat <<'EOF'
Usage: orchestrator-compose.sh --env-file PATH <compose-command> [args...]

Runs the tracked RunSecure orchestrator Compose stack. Commands that can
create or start services first require the scope's GitHub credential to
resolve to a regular, non-symlink file owned by the invoking UID with mode
exactly 0400.

Which credential is required is read from auth.type in the scope YAML named
by RUNSECURE_SCOPE_FILE_HOST:

  auth.type: pat         requires RUNSECURE_PAT_FILE
  auth.type: github_app  requires RUNSECURE_APP_PRIVATE_KEY_FILE

A scope using github_app does not need a PAT, and vice versa.
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

# ---- Resolve which credential this scope actually needs ---------------------
# The scope file is the authority on auth.type. It is named by
# RUNSECURE_SCOPE_FILE_HOST, which may come from the env file rather than the
# ambient environment, so read the env file too. Only these specific keys are
# consulted; the env file is never sourced, so a stray line in it cannot run.
env_file_value() {
    # $1 = key. Prints the last assignment, unquoted. Ignores comments.
    sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" \
        | tail -n1 \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

SCOPE_FILE_HOST=${RUNSECURE_SCOPE_FILE_HOST:-$(env_file_value RUNSECURE_SCOPE_FILE_HOST)}
if [[ -z $SCOPE_FILE_HOST ]]; then
    echo "[RunSecure] ERROR: RUNSECURE_SCOPE_FILE_HOST is required (set it in $ENV_FILE)" >&2
    exit 1
fi
if [[ ! -f $SCOPE_FILE_HOST ]]; then
    echo "[RunSecure] ERROR: scope file is not a regular file: $SCOPE_FILE_HOST" >&2
    exit 1
fi

# Parse auth.type with the YAML parser rather than grep so an indented or
# reordered scope file cannot be misread into the wrong credential path.
AUTH_TYPE=$(python3 -c '
import sys, yaml
try:
    doc = yaml.safe_load(open(sys.argv[1])) or {}
except Exception as exc:
    print(f"__ERROR__{exc}")
    raise SystemExit(0)
auth = doc.get("auth")
if not isinstance(auth, dict):
    print("__ERROR__scope file has no auth block")
    raise SystemExit(0)
print(auth.get("type") or "__ERROR__auth.type is empty")
' "$SCOPE_FILE_HOST")

if [[ $AUTH_TYPE == __ERROR__* ]]; then
    echo "[RunSecure] ERROR: cannot read auth.type from $SCOPE_FILE_HOST: ${AUTH_TYPE#__ERROR__}" >&2
    exit 1
fi

case "$AUTH_TYPE" in
    pat)
        AUTH_SECRET_FILE=${RUNSECURE_PAT_FILE:-$(env_file_value RUNSECURE_PAT_FILE)}
        AUTH_SECRET_NAME=runsecure-pat
        AUTH_SECRET_VAR=RUNSECURE_PAT_FILE
        ;;
    github_app)
        AUTH_SECRET_FILE=${RUNSECURE_APP_PRIVATE_KEY_FILE:-$(env_file_value RUNSECURE_APP_PRIVATE_KEY_FILE)}
        AUTH_SECRET_NAME=runsecure-app-private-key
        AUTH_SECRET_VAR=RUNSECURE_APP_PRIVATE_KEY_FILE
        ;;
    *)
        echo "[RunSecure] ERROR: auth.type must be 'pat' or 'github_app' (got '$AUTH_TYPE') in $SCOPE_FILE_HOST" >&2
        exit 1
        ;;
esac

if [[ -z $AUTH_SECRET_FILE ]]; then
    echo "[RunSecure] ERROR: scope uses auth.type '$AUTH_TYPE', so $AUTH_SECRET_VAR is required" >&2
    exit 1
fi

export RUNSECURE_AUTH_SECRET_HOST_VALIDATED="$VALIDATION_SENTINEL"
export RUNSECURE_AUTH_SECRET_FILE="$AUTH_SECRET_FILE"
export RUNSECURE_AUTH_SECRET_NAME="$AUTH_SECRET_NAME"
COMPOSE_BASE=("${COMPOSE[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE")

validate_host_auth_secret() {
    "${COMPOSE_BASE[@]}" config --format json \
        | python3 "${SCRIPT_DIR}/validate-compose-auth-secret.py" \
            "$VALIDATION_SENTINEL" "$AUTH_SECRET_NAME"
}

# Teardown and read-only inspection must remain available if the credential was
# intentionally removed or its permissions drifted.  Every command capable of
# creating or starting containers takes the validated path below.
case "$COMPOSE_COMMAND" in
    down|stop|kill|rm|logs|ps|events|top|images|port|version|help)
        ;;
    *)
        validate_host_auth_secret
        ;;
esac

exec "${COMPOSE_BASE[@]}" "$@"
