#!/bin/bash
# Host-only composer regression: inspect generated builds without touching Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/project/.github"
export COMPOSE_TEST_DIR="$TEST_DIR"
cat > "$TEST_DIR/bin/docker" <<'MOCK'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$COMPOSE_TEST_DIR/docker.log"
case "$1 $2" in
    'image inspect')
        if [[ "${3:-}" == --format ]]; then
            if [[ "$4" == *composition-base* ]]; then
                echo 'ghcr.io/andend-collective/runsecure/node-build@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            else
                echo 'ghcr.io/andend-collective/runsecure/node@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            fi
            exit 0
        fi
        exit 1 ;;
    'build -f') cp "$3" "$COMPOSE_TEST_DIR/generated.Dockerfile" ;;
esac
MOCK
chmod 755 "$TEST_DIR/bin/docker"
export PATH="$TEST_DIR/bin:$PATH"
cat > "$TEST_DIR/project/.github/runner.yml" <<'YAML'
version: "2.2.0"
runtime: node:24
apt: [zip, openssh-client]
YAML
bash "$ROOT/infra/scripts/compose-image.sh" "$TEST_DIR/project" > "$TEST_DIR/output"
python3 - "$TEST_DIR/generated.Dockerfile" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
def before(first, second):
    assert text.index(first) < text.index(second), f'{first} must precede {second}'
before('ARG RUNSECURE_RUNTIME_PATH=', 'ENV PATH="/usr/local/sbin:/usr/sbin:/sbin:')
before('ENV PATH="/usr/local/sbin:/usr/sbin:/sbin:', 'RUN apt-get update')
before('RUN apt-get update', '/opt/runsecure/composition/finalize-hardening.sh')
before('/opt/runsecure/composition/finalize-hardening.sh', 'ENV PATH="${RUNSECURE_RUNTIME_PATH}"')
for label in ['LABEL io.runsecure.image-role="runtime"', 'LABEL security.hardening="full"',
              'LABEL org.opencontainers.image.title="RunSecure Project Runtime"']:
    before('/opt/runsecure/composition/finalize-hardening.sh', label)
assert '         zip \\' in text and '         openssh-client \\' in text
assert 'USER runner' in text and '&& rm -rf /opt/runsecure/composition' in text
assert 'COPY ' not in text
assert 'ssh,' not in text  # apt opt-in does not silently remove its SSH client.
print('PASS: package composition has a build-only root PATH and truthful terminal metadata')
PY
# The same immutable inputs are stable, but corrected composer code must not
# silently reuse an image cached by the old implementation.
first_image=$(tail -1 "$TEST_DIR/output")
bash "$ROOT/infra/scripts/compose-image.sh" "$TEST_DIR/project" > "$TEST_DIR/output"
test "$(tail -1 "$TEST_DIR/output")" = "$first_image"
mkdir -p "$TEST_DIR/checkout/infra/scripts/lib" "$TEST_DIR/checkout/images"
cp "$ROOT/infra/scripts/compose-image.sh" "$TEST_DIR/checkout/infra/scripts/compose-image.sh"
cp "$ROOT/infra/scripts/lib/validate-schema.sh" "$TEST_DIR/checkout/infra/scripts/lib/validate-schema.sh"
cp "$ROOT/images/node.Dockerfile" "$TEST_DIR/checkout/images/node.Dockerfile"
printf '\n# Fixture simulating a composer correction.\n' >> "$TEST_DIR/checkout/infra/scripts/compose-image.sh"
bash "$TEST_DIR/checkout/infra/scripts/compose-image.sh" "$TEST_DIR/project" > "$TEST_DIR/output"
test "$(tail -1 "$TEST_DIR/output")" != "$first_image"
echo 'PASS: identical inputs cache deterministically and corrected composer code invalidates the cache'
# The image fixture test builds these exact generated instructions against a
# uniquely named source-built stage; fake pulls above never contact a registry.
if [[ -n "${COMPOSE_TEST_DOCKERFILE:-}" ]]; then
    cat >> "$TEST_DIR/project/.github/runner.yml" <<'YAML'
hardening:
  remove: [ssh, scp, sftp, ssh-agent, ssh-add, ssh-keyscan]
YAML
    bash "$ROOT/infra/scripts/compose-image.sh" "$TEST_DIR/project" > "$TEST_DIR/output"
    cp "$TEST_DIR/generated.Dockerfile" "$COMPOSE_TEST_DOCKERFILE"
fi
# Zero additions still consume the released terminal image directly.
printf 'version: "2.2.0"\nruntime: node:24\n' > "$TEST_DIR/project/.github/runner.yml"
rm "$TEST_DIR/generated.Dockerfile"
bash "$ROOT/infra/scripts/compose-image.sh" "$TEST_DIR/project" > "$TEST_DIR/output"
test ! -e "$TEST_DIR/generated.Dockerfile"
test "$(tail -1 "$TEST_DIR/output")" = runner-node:24
echo 'PASS: unchanged no-addition configuration uses the release terminal image directly'
