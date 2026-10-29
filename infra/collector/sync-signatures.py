#!/usr/bin/env python3
"""Package PUBLIC canonical RunSecure signatures; never read private upstream."""
import argparse
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = root / '.cornerstone/events'
target = root / 'charts/runsecure-telemetry/files/events'
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
files = {p.name: p.read_bytes() for p in source.glob('*.yaml')}
existing = {p.name: p.read_bytes() for p in target.glob('*.yaml')}
if args.check:
    if files != existing:
        raise SystemExit('Chart signature snapshot differs: run infra/collector/sync-signatures.py')
else:
    target.mkdir(parents=True, exist_ok=True)
    for name in existing.keys() - files.keys():
        (target / name).unlink()
    for name, data in files.items():
        (target / name).write_bytes(data)
