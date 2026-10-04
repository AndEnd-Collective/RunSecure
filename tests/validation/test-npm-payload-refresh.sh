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
# node20 (Node 20.20.2 as of runner 2.337.0). npm 12.x declares
# `engines.node: ^22.22.2 || ^24.15.0 || >=26.0.0` and does not support Node
# 20, so base is held at the latest 11.x. node runs NodeSource Node 24 and
# takes the latest stable npm.
#
# Both must vendor the same fixed transitive deps, asserted below — that is
# the property this test actually exists to protect, and it is why holding
# base on 11.x costs nothing.
expected = {
    "base": ("11.21.0", "783e7c92bf73b442fb800c2d6ef3921e86da8894a700fed45140e37916877482"),
    "node": ("12.2.0", "6666b48816b39b86c3febac7b51a4ee4de6c5ca589c382ad8004b6b113f86677"),
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
    for package_version in ("7.5.22", "5.0.9", "6.28.0"):
        assert package_version in dockerfile, (
            f"{name} image no longer asserts fixed npm dependency {package_version}"
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
