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

expected_version = "11.18.0"
expected_sha256 = "73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e"

for name, dockerfile in (("base", base), ("node", node)):
    version = re.search(r"^ARG NPM_VERSION=([^\s]+)$", dockerfile, re.MULTILINE)
    digest = re.search(r"^ARG NPM_SHA256=([0-9a-f]{64})$", dockerfile, re.MULTILINE)
    assert version, f"{name} image must pin an exact npm version"
    assert digest, f"{name} image must pin the npm tarball SHA-256"
    assert version.group(1) == expected_version, f"{name} npm pin drifted"
    assert digest.group(1) == expected_sha256, f"{name} npm checksum drifted"
    assert 'echo "${NPM_SHA256}  /tmp/npm.tgz" | sha256sum -c -' in dockerfile
    for package_version in ("7.5.19", "5.0.7", "6.27.0"):
        assert package_version in dockerfile, (
            f"{name} image no longer asserts fixed npm dependency {package_version}"
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
