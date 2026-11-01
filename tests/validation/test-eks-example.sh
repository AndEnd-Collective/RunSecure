#!/usr/bin/env bash
# Source/Helm contract only; never contacts AWS or installs a cluster.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if ! command -v helm >/dev/null 2>&1; then
  echo 'SKIP: helm unavailable; EKS example render checks not executed'
  exit 0
fi
python3 - "$ROOT" <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml

root = Path(sys.argv[1])
example = root / 'examples/eks-bottlerocket'
values = yaml.safe_load((example / 'helm-values.example.yaml').read_text())
manifest_bytes = (example / 'runsecure-v2.2.1-release-images.json').read_bytes()
assert hashlib.sha256(manifest_bytes).hexdigest() == '86e3fe1274522214a54b024ec4470e81df02d27dd0c4533cb4b4a9ab56ce768f'
manifest = json.loads(manifest_bytes)
assert manifest['release'] == '2.2.1'
images = values['image']
for config, name in [(images['orchestrator'], 'orchestrator'), (images['proxy'], 'proxy'),
                     (images['socketProxy'], 'socket-proxy'), (images['runners']['default'], 'node-24'),
                     (images['runners']['node'], 'node-24'), (images['runners']['python'], 'python-3.12'),
                     (images['runners']['rust'], 'rust-stable')]:
    assert config['digest'] == manifest['images'][name].split('@')[1], name
assert values['scope']['repos'] == []
assert values['scope']['allowProjectOverrides'] == []
assert values['auth']['type'] == 'github_app'
assert 'value' not in values['auth'].get('pat', {})

def render(config):
    with tempfile.TemporaryDirectory(prefix='rs-eks-contract-') as tmp:
        path = Path(tmp) / 'values.yaml'
        path.write_text(yaml.safe_dump(config))
        output = subprocess.run(['helm', 'template', 'runsecure', str(root / 'charts/runsecure-orchestrator'), '-f', str(path)], capture_output=True, text=True, check=True).stdout
        return [d for d in yaml.safe_load_all(output) if d]

docs = render(values)
deployment = next(d for d in docs if d['kind'] == 'Deployment')
pod = deployment['spec']['template']['spec']
assert deployment['spec']['replicas'] == 1 and deployment['spec']['strategy']['type'] == 'Recreate'
assert pod['nodeSelector']['runsecure.io/pool'] == 'management'
assert pod['containers'][0]['image'].endswith('@' + images['orchestrator']['digest'])
assert not any(d['kind'] in ['Secret', 'ClusterRole', 'ClusterRoleBinding'] for d in docs)
scope = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['scope.yml'])
assert scope['repos'] in (None, [])

# Exercise the documented enrollment shape, not just an idle controller render.
enrolled = copy.deepcopy(values)
enrolled['scope']['repos'] = [{
    'repo': 'example/your-repository', 'namespace': 'ci-example', 'maxConcurrent': 1,
    'runnerConfig': {'runtime': 'node:24', 'labels': ['self-hosted', 'Linux', 'ARM64', 'container', 'runsecure-eks'],
                     'resources': {'memory': '2g', 'cpus': 2, 'pids': 256},
                     'httpEgress': ['github.com', 'api.github.com', 'codeload.github.com'],
                     'orchestrator': {'timeoutSeconds': 3600}},
    'kubernetes': {'nodeSelector': {'runsecure.io/pool': 'execution'},
                   'tolerations': [{'key': 'dedicated', 'operator': 'Equal', 'value': 'runsecure-execution', 'effect': 'NoSchedule'}],
                   'ephemeralStorage': '10Gi', 'proxyResources': {'cpu': '250m', 'memory': '256Mi', 'ephemeralStorage': '1Gi'}}}]
docs = render(enrolled)
scope = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['scope.yml'])
project = scope['repos'][0]
assert project['namespace'] == 'ci-example'
assert project['kubernetes']['node_selector'] == {'runsecure.io/pool': 'execution'}
assert project['runner_config']['http_egress'] == ['github.com', 'api.github.com', 'codeload.github.com']
roles = [d for d in docs if d['kind'] == 'Role']
assert [r['metadata']['namespace'] for r in roles] == ['ci-example']
for namespace in [d for d in docs if d['kind'] == 'Namespace']:
    assert namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'] == 'restricted'

dns = yaml.safe_load((example / 'platform-dns-policy.example.yaml').read_text())
assert dns['metadata']['namespace'] == 'kube-system'
assert dns['spec']['podSelector']['matchLabels'] == {'k8s-app': 'kube-dns'}
assert set(dns['spec']['policyTypes']) == {'Ingress', 'Egress'}
assert all(peer['ipBlock']['cidr'].endswith('/32') for rule in dns['spec']['egress'] for peer in rule['to'])
print('PASS: EKS empty/enrolled Helm contracts, accepted release pins, namespace authority and staged DNS example')
PY
