#!/usr/bin/env bash
# Offline rendering/schema and real compressed archive-envelope regressions.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
python3 infra/collector/sync-signatures.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s infra/collector/tests -p 'test_chart.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s examples/eks-bottlerocket/archive -p 'test_*.py'
python3 - "$ROOT" <<'PY'
import json
import pathlib
import subprocess
import sys
import yaml
root = pathlib.Path(sys.argv[1])
rendered = subprocess.check_output(['helm', 'template', 'controller', str(root/'charts/runsecure-orchestrator')], text=True)
deployment = next(d for d in yaml.safe_load_all(rendered) if d and d['kind']=='Deployment')
env = {e['name']:e for e in deployment['spec']['template']['spec']['containers'][0]['env']}
assert env['CORNERSTONE_ENV']['value']=='Testing'
for key, field in {'RUNSECURE_POD_UID':'metadata.uid','RUNSECURE_POD_NAME':'metadata.name','RUNSECURE_POD_NAMESPACE':'metadata.namespace','RUNSECURE_NODE_NAME':'spec.nodeName'}.items():
    assert env[key]['valueFrom']['fieldRef']['fieldPath']==field
assert set(['RUNSECURE_K8S_CLUSTER','RUNSECURE_CLOUD_PROVIDER','RUNSECURE_CLOUD_REGION','RUNSECURE_CLOUD_ACCOUNT_ID']) <= env.keys()
schema=json.loads((root/'charts/runsecure-orchestrator/values.schema.json').read_text())
assert schema['properties']['logging']['properties']['environment']['enum']==['Development','Testing','Staging','Production']
print('PASS: controller identity derives from Downward API and explicit canonical deployment inputs')
PY
