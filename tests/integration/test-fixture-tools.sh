#!/bin/bash
# Exercise the maintained composer with opt-in native ZIP/SSH fixture tools.
# Requires yq v4, Docker, and runner-base:latest (built by smoke-test.yml).
# Creates no fixed container names and never changes existing base/runtime tags.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Fail before invoking composer if Docker/base inspection is denied or missing;
# this test must never trigger the composer's fallback runner-base build.
docker image inspect runner-base:latest >/dev/null
TEST_DIR=$(mktemp -d)
TEST_SUFFIX="$(basename "$TEST_DIR" | tr '[:upper:]' '[:lower:]')"
BUILDER_REF="runsecure-fixture-builder:${TEST_SUFFIX}"
IMAGE_REF="runsecure-fixture-runtime:${TEST_SUFFIX}"
cleanup() {
    rm -rf "$TEST_DIR"
    docker image rm "$IMAGE_REF" "$BUILDER_REF" >/dev/null 2>&1 || true
}
# Explicitly reject tag collisions; cleanup only ever removes these test tags.
for ref in "$BUILDER_REF" "$IMAGE_REF"; do
    if docker image inspect "$ref" >/dev/null 2>&1; then
        echo "ERROR: fixture tag already exists: $ref" >&2
        exit 1
    fi
done
trap cleanup EXIT
# Capture the real composer instructions using host-only provenance fixtures.
# This never pulls or retags released images. Replace only FROM with our unique
# source-built node-build stage, preserving the generated installation/finalizer.
COMPOSE_TEST_DOCKERFILE="$TEST_DIR/composed.Dockerfile" \
    bash "$ROOT/tests/validation/test-compose-project-finalization.sh"
docker build -f "$ROOT/images/node.Dockerfile" --target node-build \
    --build-arg BASE_REF=runner-base:latest --build-arg NODE_VERSION=24 \
    -t "$BUILDER_REF" "$ROOT"
sed "s|^FROM .*|FROM ${BUILDER_REF}|" "$TEST_DIR/composed.Dockerfile" > "$TEST_DIR/Dockerfile"
docker build -f "$TEST_DIR/Dockerfile" \
    --build-arg RUNSECURE_HARDENING_REMOVE=ssh,scp,sftp,ssh-agent,ssh-add,ssh-keyscan \
    -t "$IMAGE_REF" "$ROOT"
for pair in 'io.runsecure.image-role runtime' 'security.hardening full'; do
    read -r key expected <<< "$pair"
    actual=$(docker image inspect --format "{{index .Config.Labels \"$key\"}}" "$IMAGE_REF")
    [[ "$actual" == "$expected" ]]
done
# Production-sized noexec /tmp stays separate from writable fixture storage.
docker run --rm --network none --read-only --user 1001:0 --cap-drop ALL \
    --security-opt no-new-privileges:true --entrypoint "" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,uid=1001,gid=0 \
    --tmpfs /home/runner/_work:rw,nosuid,nodev,size=64m,uid=1001,gid=0 \
    --env RUNNER_TEMP=/home/runner/_work/_temp \
    "$IMAGE_REF" bash -euo pipefail -c '
        test "$(id -u)" = 1001
        for bin in apt apt-get dpkg adduser useradd sudo su ssh scp sftp ssh-agent ssh-add ssh-keyscan; do
            if command -v "$bin" >/dev/null 2>&1; then
                echo "FAIL: forbidden runtime tool is present: $bin" >&2
                exit 1
            fi
        done
        test ! -e /opt/runsecure/composition
        test "$(stat -c %a /etc)" = 555
        test "$(stat -c %a /var/lib/dpkg/status)" = 444
        case ":$PATH:" in *:/usr/sbin:*|*:/sbin:*|*:/usr/local/sbin:*) exit 1;; esac
        test -z "$(find /usr /bin -perm /6000 -type f -print -quit)"
        node --version
        npm --version
        mkdir -p "$RUNNER_TEMP/defense-quality"
        export TMPDIR="$RUNNER_TEMP/defense-quality"
        fixture=$(mktemp -d)
        trap '\''rm -rf "$fixture"'\'' EXIT
        cd "$fixture"
        printf "native archive fixture\n" > source.txt
        zip -q fixture.zip source.txt
        unzip -q fixture.zip -d extracted
        cmp source.txt extracted/source.txt
        ssh-keygen -q -t ed25519 -N "" -f key
        ssh-keygen -y -f key > derived.pub
        test "$(cut -d " " -f1,2 key.pub)" = "$(cut -d " " -f1,2 derived.pub)"
        printf "fixture %s\n" "$(cat key.pub)" > allowed_signers
        ssh-keygen -Y sign -f key -n runsecure-fixture source.txt
        ssh-keygen -Y verify -f allowed_signers -I fixture -n runsecure-fixture \
            -s source.txt.sig < source.txt
        echo "PASS: ZIP roundtrip and SSH sign/verify under terminal runner hardening"
    '
echo "PASS: composer fixture runtime metadata, PATH, package removal, and native tools ($IMAGE_REF)"
