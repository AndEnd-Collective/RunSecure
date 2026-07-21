#!/bin/bash
# Static supply-chain assertions for the scanner bootstrap used by PR and
# release image gates.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNSECURE_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
INSTALLER=${RUNSECURE_ROOT}/infra/scripts/install-pinned-scanners.sh
PUBLISH=${RUNSECURE_ROOT}/.github/workflows/publish-images.yml
PR_SCAN=${RUNSECURE_ROOT}/.github/workflows/grype-scan.yml

python3 - "$INSTALLER" "$PUBLISH" "$PR_SCAN" <<'PY'
import pathlib
import re
import sys

installer = pathlib.Path(sys.argv[1]).read_text()
workflows = [pathlib.Path(path).read_text() for path in sys.argv[2:]]

assert "/main/install.sh" not in installer
assert "/releases/latest" not in installer
assert "DOWNLOAD_TAG_INSTALL_SCRIPT=false" in installer

for tool in ("SYFT", "GRYPE"):
    version = re.search(rf"^{tool}_VERSION=(v[0-9]+\.[0-9]+\.[0-9]+)$", installer, re.M)
    commit = re.search(rf"^{tool}_INSTALL_COMMIT=([0-9a-f]{{40}})$", installer, re.M)
    installer_sum = re.search(rf"^{tool}_INSTALL_SHA256=([0-9a-f]{{64}})$", installer, re.M)
    binary_sums = {
        arch: re.search(
            rf"^{tool}_BINARY_SHA256_{arch}=([0-9a-f]{{64}})$", installer, re.M
        )
        for arch in ("AMD64", "ARM64")
    }
    assert version, f"{tool} version is not exact"
    assert commit, f"{tool} installer commit is not immutable"
    assert installer_sum, f"{tool} installer checksum is not pinned"
    assert all(binary_sums.values()), f"{tool} binary checksums are not pinned"

assert installer.count("sha256sum -c -") >= 2
assert '"$binary" version | grep -F' in installer

for workflow in workflows:
    assert "infra/scripts/install-pinned-scanners.sh /usr/local/bin" in workflow
    assert "anchore/syft/main/install.sh" not in workflow
    assert "anchore/grype/main/install.sh" not in workflow
PY

bash -n "$INSTALLER"
echo "PASS: scanner installers, versions, and binaries are checksum-pinned"
