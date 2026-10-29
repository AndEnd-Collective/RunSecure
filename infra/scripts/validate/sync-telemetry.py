#!/usr/bin/env python3
"""Generate/check module-local copies of RunSecure's canonical telemetry helper."""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "infra" / "telemetry"
TARGETS = [ROOT / "infra" / module / "internal" / "telemetry" for module in ("orchestrator", "socket-proxy", "collector/processor")]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = {p.name: p.read_bytes() for p in SOURCE.glob("*.go")}
    if not expected:
        raise SystemExit("canonical telemetry Go sources missing")
    drift = []
    for target in TARGETS:
        if not args.check:
            target.mkdir(parents=True, exist_ok=True)
        actual = {p.name for p in target.glob("*.go")}
        for name, content in expected.items():
            path = target / name
            if args.check:
                if not path.is_file() or path.read_bytes() != content:
                    drift.append(str(path.relative_to(ROOT)))
            else:
                path.write_bytes(content)
        for name in actual - expected.keys():
            drift.append(str((target / name).relative_to(ROOT)))
    if drift:
        print("telemetry mirror drift: " + ", ".join(drift), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
