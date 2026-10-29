#!/usr/bin/env python3
"""Operator-run preflight: GET + server-side dry-run only; persists no Pods.

Requires PyYAML. Never installs/updates the guard, deploys a chart or changes IAM.
Run after reviewed guard-only installation, before a live workload upgrade.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--context', required=True, help='Explicit reviewed kubectl context')
parser.add_argument('--values', required=True, type=Path, help='Qualified values containing no credentials')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
kubectl = ['kubectl', '--context', args.context, '--request-timeout=15s']


def get(kind):
    return json.loads(subprocess.check_output(kubectl+['get', kind, 'runsecure-telemetry-node-reader', '-o', 'json'], text=True))


policy = get('validatingadmissionpolicy')
binding = get('validatingadmissionpolicybinding')
status = policy.get('status', {})
if status.get('observedGeneration') != policy['metadata']['generation']:
    raise SystemExit('Admission policy has not observed its latest generation')
if 'typeChecking' not in status:
    raise SystemExit('Admission policy type checking has not completed')
if status.get('typeChecking', {}).get('expressionWarnings'):
    raise SystemExit('Admission policy has CEL type-checking warnings')
if policy['spec']['failurePolicy'] != 'Fail' or binding['spec']['validationActions'] != ['Deny']:
    raise SystemExit('Admission policy/binding is not fail-closed Deny')

render = subprocess.check_output(['helm', 'template', 'telemetry', str(root/'charts/runsecure-telemetry'), '-f', str(args.values), '--set', 'enabled=true', '--set', 'renderOnly=true', '--set', 'nodeReader.installGuardOnly=false'], text=True)
documents = [d for d in yaml.safe_load_all(render) if d]
expected = next(d for d in documents if d['kind']=='ValidatingAdmissionPolicy')
for field in ['validations', 'matchConditions']:
    if policy['spec'][field] != expected['spec'][field]:
        raise SystemExit('Live admission guard differs from exact chart guard: '+field)
daemon = next(d for d in documents if d['kind']=='DaemonSet')
spec = daemon['spec']['template']['spec']
spec.pop('initContainers', None)
spec['nodeSelector'].pop('runsecure.io/telemetry-render-only', None)
pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'runsecure-telemetry-admission-preflight', 'namespace': 'runsecure-observability-node'}, 'spec': spec}


def dry_run(candidate):
    return subprocess.run(kubectl+['create', '--dry-run=server', '-f', '-', '-o', 'json'], input=json.dumps(candidate), text=True, capture_output=True)


accepted = dry_run(pod)
if accepted.returncode != 0:
    raise SystemExit('Exact reader positive admission dry-run failed: '+accepted.stderr)
for label, mutation in [
    ('host root', lambda p: p['spec']['volumes'][0]['hostPath'].update(path='/')),
    ('privileged', lambda p: p['spec']['containers'][0]['securityContext'].update(privileged=True)),
    ('host network', lambda p: p['spec'].update(hostNetwork=True))
]:
    unsafe = copy.deepcopy(pod)
    mutation(unsafe)
    denied = dry_run(unsafe)
    if denied.returncode == 0 or 'runsecure-telemetry-node-reader' not in denied.stderr or 'denied' not in denied.stderr.lower():
        raise SystemExit('Expected named guard did not deny '+label+': '+denied.stderr)
print('PASS: latest compiled guard accepts exact reader and denies host-root/privileged/network dry-runs; no Pod persisted')
