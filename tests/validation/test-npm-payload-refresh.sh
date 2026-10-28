#!/bin/bash
# Static contract for the checksum-pinned npm payload installed into both the
# actions-runner's private Node runtimes and the workflow-facing Node image.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNSECURE_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

python3 - \
    "${RUNSECURE_ROOT}/images/base.Dockerfile" \
    "${RUNSECURE_ROOT}/images/node.Dockerfile" \
    "${RUNSECURE_ROOT}/.grype.yaml" <<'PY'
import pathlib
import re
import sys

base = pathlib.Path(sys.argv[1]).read_text()
node = pathlib.Path(sys.argv[2]).read_text()
grype = pathlib.Path(sys.argv[3]).read_text()

# The two images intentionally pin different npm majors.
#
# base installs npm into the actions-runner's private externals, which include
# node20. npm 12.x declares
# `engines.node: ^22.22.2 || ^24.15.0 || >=26.0.0` and does not support Node
# 20, so base is held at the latest 11.x. node runs NodeSource Node 24 and
# takes the latest stable npm.
#
# Both must vendor the same fixed transitive deps, asserted below — that is
# the property this test actually exists to protect, and it is why holding
# base on 11.x costs nothing.
expected = {
    "base": ("11.21.1", "dd77c48eb845f4856c2cdba347cfb52bd877a2655a1ea48ff0c4796e3df9dd7b"),
    "node": ("12.2.1", "228bd64aaef23270dbdbd2cf3d5ef5c467602ef38c4066246cef1984adab9a67"),
}

for name, dockerfile in (("base", base), ("node", node)):
    expected_version, expected_sha256 = expected[name]
    version = re.search(r"^ARG NPM_VERSION=([^\s]+)$", dockerfile, re.MULTILINE)
    digest = re.search(r"^ARG NPM_SHA256=([0-9a-f]{64})$", dockerfile, re.MULTILINE)
    assert version, f"{name} image must pin an exact npm version"
    assert digest, f"{name} image must pin the npm tarball SHA-256"
    assert version.group(1) == expected_version, (
        f"{name} npm pin drifted: expected {expected_version}, found {version.group(1)}"
    )
    assert digest.group(1) == expected_sha256, f"{name} npm checksum drifted"
    assert 'echo "${NPM_SHA256}  /tmp/npm.tgz" | sha256sum -c -' in dockerfile
    # tar is asserted as a literal (npm bundles a fixed version); undici and
    # brace-expansion are asserted through ARGs because the images keep their
    # checksum-pinned dependency payloads aligned.
    assert "7.5.22" in dockerfile, f"{name} image no longer asserts fixed npm tar"
    for arg, version in (("UNDICI", "6.29.1"), ("BRACE_EXPANSION", "5.0.12")):
        assert f"ARG {arg}_VERSION={version}" in dockerfile, (
            f"{name} image must pin {arg}_VERSION={version}"
        )
        assert re.search(rf"^ARG {arg}_SHA256=[0-9a-f]{{64}}$", dockerfile, re.MULTILINE), (
            f"{name} image must pin the {arg} tarball SHA-256"
        )
        assert f'= "${{{arg}_VERSION}}"' in dockerfile, (
            f"{name} image must assert the installed {arg} version from the ARG"
        )
        assert f'echo "${{{arg}_SHA256}}' in dockerfile, (
            f"{name} image must checksum-verify the {arg} tarball"
        )

# Both images must overwrite the same versions, or the runner's npm and the
# workflow-facing npm drift apart.
for arg in ("UNDICI", "BRACE_EXPANSION"):
    base_pin = re.search(rf"^ARG {arg}_VERSION=(\S+)$", base, re.MULTILINE)
    node_pin = re.search(rf"^ARG {arg}_VERSION=(\S+)$", node, re.MULTILINE)
    assert base_pin and node_pin and base_pin.group(1) == node_pin.group(1), (
        f"{arg}_VERSION differs between the base and node images"
    )

# These advisories are why the overwrite exists. They must never be
# suppressed in .grype.yaml instead of fixed.
for advisory in (
    "GHSA-rfgv-xxqx-mfg5",
    "GHSA-xjj6-f33q-929c",
    "GHSA-qrxm-fqhp-jwvm",
    "GHSA-2m5v-pch6-74hx",
    "GHSA-6j4f-fj2g-mc7p",
    "GHSA-qhr7-859c-m2p7",
):
    assert advisory not in grype, (
        f"npm bundled-dependency advisory must be fixed, not ignored: {advisory}"
    )

# Guard the compatibility reasoning itself: if someone bumps base to npm 12+
# the node20 external silently gets an npm that cannot run, and nothing else
# in the suite would catch it.
base_major = int(expected["base"][0].split(".")[0])
assert base_major < 12, (
    "base image npm must stay below 12 while the runner ships a node20 "
    "external; npm 12+ requires Node >= 22.22.2"
)

assert "for NODE_RUNTIME in node20 node24" in base
assert "${NODE_PREFIX}/lib/node_modules/npm" in base
assert 'NPM_ROOT="$(npm root --global)"' in node

for advisory in (
    "GHSA-23hp-3jrh-7fpw",
    "GHSA-8x88-c5mf-7j5w",
    "GHSA-3jxr-9vmj-r5cp",
    "GHSA-vxpw-j846-p89q",
):
    assert advisory not in grype, f"fixed npm advisory must not be ignored: {advisory}"
PY

echo "PASS: npm payload and fixed transitive dependencies are checksum-pinned"

# Optional image integration check. The immutable runner externals and the
# workflow npm must execute as the hardened runtime user with browser storage
# disabled, and both npm installations must resolve the patched dependencies.
if [[ $# -gt 0 ]]; then
    [[ $# -eq 1 ]] || { echo "Usage: $0 [NODE_IMAGE]" >&2; exit 2; }
    IMAGE_REF=$1
    NPM_BASE=$(sed -n 's/^ARG NPM_VERSION=//p' "${RUNSECURE_ROOT}/images/base.Dockerfile")
    NPM_NODE=$(sed -n 's/^ARG NPM_VERSION=//p' "${RUNSECURE_ROOT}/images/node.Dockerfile")
    UNDICI=$(sed -n 's/^ARG UNDICI_VERSION=//p' "${RUNSECURE_ROOT}/images/base.Dockerfile")
    BRACE_EXPANSION=$(sed -n 's/^ARG BRACE_EXPANSION_VERSION=//p' "${RUNSECURE_ROOT}/images/base.Dockerfile")
    docker run --rm --read-only --tmpfs /tmp --user 1001:0 \
        --cap-drop=ALL --security-opt=no-new-privileges --network none \
        --env NODE_OPTIONS=--no-experimental-webstorage --entrypoint bash \
        "$IMAGE_REF" -ceu '
        test "$(npm --version)" = "$1"
        test "$(node -p "typeof localStorage")" = undefined
        for runtime in node20 node24; do
            prefix="/home/runner/actions-runner/externals/$runtime"
            # Node 20 predates the Web Storage experiment and rejects its flag.
            # Assert that storage is absent before running its npm CLI.
            options=$NODE_OPTIONS
            if [[ "$runtime" == node20 ]]; then options=; fi
            test "$(NODE_OPTIONS="$options" "$prefix/bin/node" -p "typeof localStorage")" = undefined
            test "$(NODE_OPTIONS="$options" "$prefix/bin/node" "$prefix/lib/node_modules/npm/bin/npm-cli.js" --version)" = "$2"
        done
        for modules in /usr/lib/node_modules/npm/node_modules \
            /home/runner/actions-runner/externals/node20/lib/node_modules/npm/node_modules \
            /home/runner/actions-runner/externals/node24/lib/node_modules/npm/node_modules; do
            node - "$modules" "$3" "$4" <<\JS
const assert = require("node:assert/strict");
const [modules, undici, brace] = process.argv.slice(2);
assert.equal(require(`${modules}/undici/package.json`).version, undici);
assert.equal(require(`${modules}/brace-expansion/package.json`).version, brace);
assert.equal(require(`${modules}/tar/package.json`).version, "7.5.22");
JS
        done
    ' bash "$NPM_NODE" "$NPM_BASE" "$UNDICI" "$BRACE_EXPANSION"
    echo "PASS: hardened npm payloads execute with browser storage disabled"
fi
