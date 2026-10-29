#!/bin/bash
# Self-CI requires a composed image; generic terminal acceptance runners must
# neither create capacity for it nor match its GitHub assignment labels.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 - "$ROOT/.github/workflows/dogfood.yml" "$ROOT/.github/runner.yml" <<'PY'
import pathlib
import sys

import yaml

workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
project = yaml.safe_load(pathlib.Path(sys.argv[2]).read_text())
required = {label.lower() for label in workflow['jobs']['lints-on-self']['runs-on']}
configured = {label.lower() for label in project['labels']}
assert 'runsecure-dogfood' in required, 'dogfood can still run on generic terminal runners'
assert required == configured, 'dogfood workflow and composed runner labels differ'
assert required == {'self-hosted', 'linux', 'arm64', 'container', 'runsecure-dogfood'}
assert 'python3-pip' in project.get('apt', []), 'composed self-CI image must include pip'
print('PASS: dogfood workflow and project configuration require matching dedicated labels')
# GitHub assigns only when every requested label exists on the runner.
# The controller also checks that its available labels cover the job labels.
generic = {'self-hosted', 'linux', 'arm64', 'container'}
acceptance = generic | {'runsecure-jit', 'runsecure-scope-release-fixture'}
assert not required.issubset(generic)
assert not required.issubset(acceptance)
print('PASS: generic and acceptance terminal runners cannot match dogfood jobs')
assert required.issubset(configured)
# A dedicated one-shot runner must not claim the scope-specific live gate.
live_gate = generic | {'runsecure-scope-release-fixture'}
assert not live_gate.issubset(configured)
print('PASS: composed self-CI runner matches dogfood and cannot claim scope-specific acceptance')
PY
