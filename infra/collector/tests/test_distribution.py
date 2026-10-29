#!/usr/bin/env python3
"""Exercise the assembled binary against local CRI and fake CloudWatch APIs.

No real AWS credentials/services or Kubernetes cluster are used. The fake HTTP
endpoint is bound only to loopback and static credentials are obvious fixtures.
"""
import copy
import datetime
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[3]
BINARY = os.environ.get('COLLECTOR_BINARY', '')


def rendered_configs():
    output = subprocess.check_output(['helm', 'template', 'telemetry', str(ROOT/'charts/runsecure-telemetry'), '-f', str(Path(__file__).parent/'values.render.yaml')], text=True)
    return {d['metadata']['name']: yaml.safe_load(d['data']['config.yaml']) for d in yaml.safe_load_all(output) if d and d['kind']=='ConfigMap' and 'config.yaml' in d['data']}


def event():
    return {'event.uuid': '12345678-1234-4234-9234-123456789012',
            'event.definition.uuid': '31e356a8-ac36-45c4-802f-7a8228627475',
            'event.signature': 'runsecure-orchestrator-v1',
            'event.sub.type': 'runsecure.orchestrator.process.started',
            'event.type': 'Activity', 'time.stamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'deployment.environment': 'Development',
            'event.details': {'summary': 'fixture controller started', 'message': 'fixture token="opaque-value"', 'severity': 6, 'result': 'success'}}


def attrs(record):
    return record.get('attributes', {})


class CWL(http.server.BaseHTTPRequestHandler):
    records = []
    requests = []
    def log_message(self, *_):
        pass
    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        target = self.headers.get('X-Amz-Target', '').split('.')[-1]
        type(self).requests.append((target, data))
        if target == 'PutLogEvents':
            type(self).records.extend(json.loads(item['message']) for item in data['logEvents'])
        response = {'logStreams': [{'logStreamName': 'collector-gateway', 'uploadSequenceToken': 'fixture'}], 'nextSequenceToken': 'fixture'}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-amz-json-1.1')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(BINARY, 'Set COLLECTOR_BINARY to the assembled binary; never substitute a stock contrib binary')
class DistributionFixture(unittest.TestCase):
    def test_cri_origin_adapter_private_validation_cwl_and_redaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            server = http.server.HTTPServer(('127.0.0.1', 0), CWL)
            CWL.records, CWL.requests = [], []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            source = tmp/'pods'
            def write(namespace, pod, container, payload):
                path = source/f'{namespace}_{pod}_12345678-1234-4234-9234-123456789012'/container/'0.log'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('2026-10-29T00:00:00.000000000Z stdout F '+payload+'\n')
            trusted = event()
            write('runsecure-eks', 'runsecure-controller-fixture', 'orchestrator', json.dumps(trusted))
            bad_definition = event()
            bad_definition['event.definition.uuid'] = '00000000-0000-4000-8000-000000000000'
            bad_definition['event.details']['summary'] = 'fixture unknown definition'
            write('runsecure-eks', 'runsecure-controller-unknown', 'orchestrator', json.dumps(bad_definition))
            bad_subtype = event()
            bad_subtype['event.sub.type'] = 'runsecure.orchestrator.not-registered'
            bad_subtype['event.details']['summary'] = 'fixture unknown subtype'
            write('runsecure-eks', 'runsecure-controller-subtype', 'orchestrator', json.dumps(bad_subtype))
            forged = event()
            forged['event.details']['summary'] = 'forged workload claim password=super-secret-fixture'
            forged['cornerstone.validated'] = True
            forged['_aws'] = {'LogGroupName': '/attacker/group', 'LogStreamName': 'attacker-stream'}
            write('ci-example', 'runsecure-controller-fixture', 'orchestrator', json.dumps(forged))
            write('kube-system', 'aws-node-fixture', 'aws-node', 'cni diagnostic token=ghp_fixtureTokenWhichMustNeverEscape1234567890')
            cfg = rendered_configs()['runsecure-telemetry-gateway']
            cfg['extensions'] = {'file_storage': {'directory': str(tmp/'state'), 'create_directory': True}}
            cfg['receivers'] = {'filelog/fixture': {
                'include': [str(source/'*/*/*.log')], 'include_file_path': True, 'start_at': 'beginning',
                'resource': {'rs.source.class': 'cri'}, 'storage': 'file_storage',
                'operators': [{'type': 'container', 'format': 'containerd', 'add_metadata_from_filepath': True}]}}
            cfg['processors']['cornerstone_validator']['signatures']['file'] = str(ROOT/'.cornerstone/events')
            cfg['exporters']['awscloudwatchlogs']['endpoint'] = f'http://127.0.0.1:{server.server_port}'
            cfg['exporters']['awscloudwatchlogs']['sending_queue']['num_consumers'] = 1
            del cfg['exporters']['awscloudwatchlogs/diagnostics']
            cfg['service']['extensions'] = ['file_storage']
            cfg['service']['pipelines'] = {'logs': {
                'receivers': ['filelog/fixture'], 'processors': cfg['service']['pipelines']['logs']['processors'], 'exporters': ['awscloudwatchlogs']}}
            cfg['service']['telemetry'] = {'logs': {'level': 'warn', 'encoding': 'json', 'output_paths': [str(tmp/'collector.json')]}, 'metrics': {'level': 'none', 'readers': []}}
            config = tmp/'config.yaml'
            config.write_text(yaml.safe_dump(cfg))
            env = dict(os.environ, AWS_ACCESS_KEY_ID='fixture-key-not-real', AWS_SECRET_ACCESS_KEY='fixture-secret-not-real', AWS_EC2_METADATA_DISABLED='true')
            with (tmp/'stderr').open('w+') as errors:
                process = subprocess.Popen([BINARY, '--config='+str(config)], env=env, stdout=errors, stderr=errors)
                try:
                    deadline = time.monotonic()+25
                    while len(CWL.records)<5 and process.poll() is None and time.monotonic()<deadline:
                        time.sleep(.1)
                    if process.poll() is not None or len(CWL.records)<5:
                        errors.seek(0)
                        diagnostics = (tmp/'collector.json').read_text() if (tmp/'collector.json').exists() else ''
                        self.fail('Collector fixture did not deliver: '+errors.read()+' '+diagnostics)
                    serialized = json.dumps(CWL.records)
                    self.assertNotIn('super-secret-fixture', serialized)
                    self.assertNotIn('opaque-value', serialized)
                    self.assertNotIn('ghp_fixtureTokenWhichMustNeverEscape1234567890', serialized)
                    records = {json.loads(r['body'])['event.details']['summary']: r for r in CWL.records}
                    promoted = records['fixture controller started']
                    self.assertEqual('runsecure-orchestrator-v1', attrs(promoted)['cornerstone.event.signature'])
                    self.assertIs(attrs(promoted)['cornerstone.validation.schema.validated'], True, attrs(promoted))
                    self.assertIs(attrs(promoted)['cornerstone.validation.signature.validated'], True)
                    self.assertNotIn('cornerstone.validation.provenance', attrs(promoted))
                    for invalid in ['fixture unknown definition', 'fixture unknown subtype']:
                        self.assertIs(attrs(records[invalid])['cornerstone.validation.signature.validated'], False)
                        self.assertIs(attrs(records[invalid])['cornerstone.validated'], False)
                    raw = [r for r in CWL.records if attrs(r).get('cornerstone.event.signature')=='runsecure-telemetry-v1']
                    self.assertEqual(2, len(raw), 'workload and infrastructure logs must remain capture events')
                    for receipt in raw:
                        self.assertIs(attrs(receipt)['cornerstone.validation.schema.validated'], True)
                        self.assertIs(attrs(receipt)['cornerstone.validation.signature.validated'], True)
                    for target, request in CWL.requests:
                        if target=='PutLogEvents':
                            self.assertEqual('/runsecure/fixture/telemetry', request['logGroupName'])
                            self.assertEqual('collector-gateway', request['logStreamName'])
                finally:
                    process.send_signal(signal.SIGTERM)
                    try: process.wait(timeout=12)
                    except subprocess.TimeoutExpired: process.kill();process.wait()
                    server.shutdown();server.server_close();thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
