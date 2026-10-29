#!/bin/bash
# Execute the Docker fixture's actual forbidden-tool guard on the host with a
# controlled PATH. A present binary must fail even when Bash errexit is enabled.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 - "$ROOT/tests/integration/test-fixture-tools.sh" <<'PY'
import pathlib
import re
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r'^\s*(for bin in ([^;]+); do\n.*?^\s*done)\s*$', source,
                  re.MULTILINE | re.DOTALL)
assert match is not None, 'fixture forbidden-tool guard not found'
guard, names = match.group(1), match.group(2).split()
with tempfile.TemporaryDirectory(prefix='runsecure-fixture-guard-') as directory:
    def run_guard():
        return subprocess.run(['/bin/bash', '-euo', 'pipefail', '-c', guard],
                              env={'PATH': directory}, capture_output=True, text=True)
    result = run_guard()
    assert result.returncode == 0, result.stderr
    print('PASS: fixture guard accepts a PATH without forbidden tools')
    for name in names:
        binary = pathlib.Path(directory, name)
        binary.write_text('#!/bin/sh\nexit 0\n')
        binary.chmod(0o755)
        result = run_guard()
        binary.unlink()
        assert result.returncode != 0, f'fixture guard silently accepted {name}'
        assert name in result.stderr, f'fixture guard did not identify {name}'
        print(f'PASS: fixture guard fails explicitly when {name} is present')
PY
