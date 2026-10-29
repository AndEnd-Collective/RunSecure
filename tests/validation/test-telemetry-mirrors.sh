#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "$ROOT/infra/scripts/validate/sync-telemetry.py" --check
python3 - "$ROOT" <<'PY'
import pathlib
import shutil
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="runsecure-telemetry-mirror-") as directory:
    root = pathlib.Path(directory)
    helper = root / "infra/scripts/validate/sync-telemetry.py"
    helper.parent.mkdir(parents=True)
    shutil.copyfile(source / helper.relative_to(root), helper)
    canonical = root / "infra/telemetry"
    canonical.mkdir(parents=True)
    for path in (source / "infra/telemetry").glob("*.go"):
        shutil.copyfile(path, canonical / path.name)
    def run(*args, ok=True):
        result = subprocess.run([sys.executable, str(helper), *args], capture_output=True, text=True)
        if (result.returncode == 0) != ok:
            raise AssertionError(result.stdout + result.stderr)
        return result
    run()
    run("--check")
    mirror = root / "infra/socket-proxy/internal/telemetry/telemetry.go"
    mirror.write_text(mirror.read_text() + "\n// introduced drift\n")
    assert "telemetry mirror drift" in run("--check", ok=False).stderr
    run()
    run("--check")
    mirror.unlink()
    run("--check", ok=False)
    run()
    extra = mirror.with_name("unexpected.go")
    extra.write_text("package telemetry\n")
    run("--check", ok=False)
    extra.unlink()
    run("--check")
print("PASS: canonical telemetry copies agree; modified, missing and foreign Go files fail closed")
PY
