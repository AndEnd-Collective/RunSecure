#!/usr/bin/env python3
"""Validate role-specific Linux images and a read-only real journal fixture."""
import datetime
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import unittest
import uuid
import yaml

ROOT = Path(__file__).resolve().parents[3]
GATEWAY_IMAGE = os.environ.get('COLLECTOR_GATEWAY_IMAGE', '')
NODE_IMAGE = os.environ.get('COLLECTOR_NODE_IMAGE', '')
# A disposable producer; no source or credentials enter this build context.
JOURNAL_PRODUCER = '''FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends systemd && rm -rf /var/lib/apt/lists/*
'''


@unittest.skipUnless(GATEWAY_IMAGE and NODE_IMAGE, 'Set COLLECTOR_GATEWAY_IMAGE and COLLECTOR_NODE_IMAGE to unpublished role images')
class LinuxImage(unittest.TestCase):
    def test_gateway_contains_only_static_collector_and_ca_bundle(self):
        # Inspect shipped image layers: docker export injects container-local
        # /dev/console, /etc/mtab and resolver files even into a scratch image.
        with tempfile.TemporaryDirectory() as temporary:
            saved = Path(temporary)/'gateway-image.tar'
            subprocess.run(['docker', 'image', 'save', '--output', str(saved), GATEWAY_IMAGE], check=True, capture_output=True)
            files, bundle = set(), None
            with tarfile.open(saved) as image:
                manifest = json.load(image.extractfile('manifest.json'))
                self.assertEqual(1, len(manifest))
                for layer in manifest[0]['Layers']:
                    with tarfile.open(fileobj=image.extractfile(layer), mode='r|*') as archive:
                        for entry in archive:
                            if not (entry.isfile() or entry.issym() or entry.islnk()):
                                continue
                            name = entry.name.removeprefix('./')
                            files.add(name)
                            if name == 'etc/ssl/certs/ca-certificates.crt':
                                bundle = archive.extractfile(entry).read().decode('ascii')
            allowed = {'usr/local/bin/runsecure-collector', 'etc/ssl/certs/ca-certificates.crt'}
            unexpected = sorted(files-allowed)
            self.assertEqual(0, len(unexpected), f'{len(unexpected)} unexpected image files; first 20: {unexpected[:20]}')
            self.assertEqual(allowed, files)
            self.assertGreater(len(bundle), 100000)
            trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            trust.load_verify_locations(cadata=bundle)
            names = {value for cert in trust.get_ca_certs() for rdn in cert['subject'] for key, value in rdn if key == 'commonName'}
            self.assertIn('Amazon Root CA 1', names)
            normalized = {''.join(c.lower() for c in name if c.isalnum()) for name in names}
            self.assertNotIn('emsigneccrootcag3', normalized)
            self.assertNotIn('aaacertificateservices', normalized)
        for tool in ['/bin/sh', '/usr/bin/journalctl']:
            result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--entrypoint', tool, GATEWAY_IMAGE], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode, tool+' unexpectedly available')

    def test_actual_agent_and_gateway_configs(self):
        render = subprocess.check_output(['helm', 'template', 'telemetry', str(ROOT/'charts/runsecure-telemetry'), '-f', str(Path(__file__).parent/'values.render.yaml')], text=True)
        # Colima shares /Users; macOS /var/folders directories may be invisible.
        with tempfile.TemporaryDirectory(dir=os.environ.get('COLLECTOR_FIXTURE_DIR', ROOT.parent/'deployment-tools')) as temporary:
            tmp = Path(temporary)
            tmp.chmod(0o755)
            shutil.copytree(ROOT/'.cornerstone/events', tmp/'events')
            for document in yaml.safe_load_all(render):
                if not document or document['kind']!='ConfigMap' or 'config.yaml' not in document['data']:
                    continue
                name = document['metadata']['name']
                config = tmp/(name+'.yaml')
                config.write_text(document['data']['config.yaml'])
                state = tmp/(name+'-state')
                state.mkdir(mode=0o777)
                state.chmod(0o777)
                node = name.endswith('node')
                image, user = (NODE_IMAGE, '0:0') if node else (GATEWAY_IMAGE, '10001:10001')
                command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', user, '-e', 'NODE_NAME=fixture-node', '-v', str(tmp)+':/fixture:ro', '-v', str(tmp/'events')+':/etc/otel-events:ro', '-v', str(state)+':/var/lib/otel:rw', image, 'validate', '--config=/fixture/'+config.name]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, result.returncode, name+': '+result.stderr)

    def test_nonroot_gateway_starts_and_emits_validated_redacted_event(self):
        render = subprocess.check_output(['helm', 'template', 'telemetry', str(ROOT/'charts/runsecure-telemetry'), '-f', str(Path(__file__).parent/'values.render.yaml')], text=True)
        cfg = next(yaml.safe_load(d['data']['config.yaml']) for d in yaml.safe_load_all(render) if d and d['kind']=='ConfigMap' and d['metadata']['name']=='runsecure-telemetry-gateway')
        with tempfile.TemporaryDirectory(dir=os.environ.get('COLLECTOR_FIXTURE_DIR', ROOT.parent/'deployment-tools')) as temporary:
            tmp = Path(temporary)
            tmp.chmod(0o755)
            shutil.copytree(ROOT/'.cornerstone/events', tmp/'events')
            source = tmp/'pods/runsecure-eks_runsecure-controller-fixture_12345678-1234-4234-9234-123456789012/orchestrator/0.log'
            source.parent.mkdir(parents=True)
            event = {'event.uuid': '12345678-1234-4234-9234-123456789012',
                     'event.definition.uuid': '31e356a8-ac36-45c4-802f-7a8228627475',
                     'event.signature': 'runsecure-orchestrator-v1',
                     'event.sub.type': 'runsecure.orchestrator.process.started',
                     'event.type': 'Activity',
                     'time.stamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'deployment.environment': 'Development',
                     'event.details': {'summary': 'scratch gateway startup fixture', 'message': 'fixture token="scratch-secret-must-be-redacted"', 'severity': 6, 'result': 'success'}}
            source.write_text('2026-10-29T00:00:00.000000000Z stdout F '+json.dumps(event)+'\n')
            cfg['extensions'] = {'file_storage': {'directory': '/var/lib/otel/storage', 'create_directory': True}}
            cfg['receivers'] = {'filelog/fixture': {
                'include': ['/fixture/pods/*/*/*.log'], 'include_file_path': True, 'start_at': 'beginning',
                'resource': {'rs.source.class': 'cri'}, 'storage': 'file_storage',
                'operators': [{'type': 'container', 'format': 'containerd', 'add_metadata_from_filepath': True}]}}
            cfg['exporters'] = {'file': {'path': '/var/lib/otel/output.json', 'flush_interval': '100ms', 'rotation': {'max_megabytes': 1, 'max_backups': 1, 'max_days': 1}}}
            cfg['service']['extensions'] = ['file_storage']
            # Preserve the rendered gateway processors, including their ordering.
            cfg['service']['pipelines'] = {'logs': {
                'receivers': ['filelog/fixture'], 'processors': cfg['service']['pipelines']['logs']['processors'], 'exporters': ['file']}}
            cfg['service']['telemetry'] = {'logs': {'level': 'warn', 'encoding': 'json', 'output_paths': ['/var/lib/otel/diagnostics.json']}, 'metrics': {'level': 'none', 'readers': []}}
            (tmp/'config.yaml').write_text(yaml.safe_dump(cfg))
            # Docker copy cannot read Colima's container tmpfs namespace. Use
            # a fixture-owned bind instead; fixed input, rotation and timeout
            # bound its contents, and only this disposable state is writable.
            state = tmp/'state'
            state.mkdir(mode=0o777)
            state.chmod(0o777)
            # Precreate storage so the host can clean it on Linux where UID
            # 10001 is not remapped to the invoking fixture user.
            (state/'storage').mkdir(mode=0o777)
            (state/'storage').chmod(0o777)
            name = 'runsecure-gateway-startup-'+uuid.uuid4().hex
            command = ['docker', 'run', '--detach', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '10001:10001', '--memory', '768m', '--cpus', '1', '--pids-limit', '64', '-v', str(state)+':/var/lib/otel:rw', '-v', str(tmp)+':/fixture:ro', '-v', str(tmp/'events')+':/etc/otel-events:ro', GATEWAY_IMAGE, '--config=/fixture/config.yaml']
            try:
                started = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(0, started.returncode, started.stderr[-4000:])
                output = state/'output.json'
                records = []
                deadline = time.monotonic()+25
                while time.monotonic()<deadline:
                    if output.exists():
                        records = []
                        for line in output.read_text().splitlines():
                            try:
                                document = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            for resource in document.get('resourceLogs', []):
                                for scope in resource.get('scopeLogs', []):
                                    records.extend(scope.get('logRecords', []))
                        if records:
                            break
                    running = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', name], text=True).strip()
                    if running != 'true':
                        break
                    time.sleep(.1)
                if not records:
                    logs = subprocess.run(['docker', 'logs', '--tail', '30', name], capture_output=True, text=True)
                    details = subprocess.check_output(['docker', 'inspect', '--format', '{{json .State}}', name], text=True)
                    diagnostics = (state/'diagnostics.json').read_text()[-6000:] if (state/'diagnostics.json').exists() else ''
                    self.fail('Gateway emitted no file records: '+details[-2000:]+' '+(logs.stdout+logs.stderr)[-4000:]+' '+diagnostics)
                self.assertEqual(1, len(records))
                attributes = {item['key']: item['value'] for item in records[0]['attributes']}
                self.assertEqual({'stringValue': 'runsecure-orchestrator-v1'}, attributes['cornerstone.event.signature'])
                self.assertEqual({'boolValue': True}, attributes['cornerstone.validation.schema.validated'])
                self.assertEqual({'boolValue': True}, attributes['cornerstone.validation.signature.validated'])
                serialized = json.dumps(records)
                self.assertIn('scratch gateway startup fixture', serialized)
                self.assertNotIn('scratch-secret-must-be-redacted', serialized)
                stopped = subprocess.run(['docker', 'stop', '--time', '10', name], capture_output=True, text=True, timeout=15)
                self.assertEqual(0, stopped.returncode, stopped.stderr[-4000:])
                code = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', name], text=True).strip()
                self.assertEqual('0', code, 'Gateway must shut down cleanly on SIGTERM')
            finally:
                subprocess.run(['docker', 'stop', '--time', '10', name], capture_output=True, text=True, timeout=15)
                subprocess.run(['docker', 'rm', '--force', name], capture_output=True, text=True, timeout=15)

    def test_journalctl_reads_separate_real_journal_without_capabilities(self):
        # The writer's writable journal never enters the reader as writable.
        # Bottlerocket format and actual unit coverage remain a live gate.
        fixture = 'runsecure-journal-fixture-'+uuid.uuid4().hex
        producer = os.environ.get('COLLECTOR_JOURNAL_PRODUCER_IMAGE', fixture+':local')
        built = 'COLLECTOR_JOURNAL_PRODUCER_IMAGE' not in os.environ
        volume = subprocess.check_output(['docker', 'volume', 'create', fixture], text=True).strip()
        try:
            if built:
                with tempfile.TemporaryDirectory() as context:
                    result = subprocess.run(['docker', 'build', '--tag', producer, '-f', '-', context], input=JOURNAL_PRODUCER, capture_output=True, text=True, timeout=240)
                    self.assertEqual(0, result.returncode, result.stderr)
            script = '''mkdir -p /run/systemd/journal
/lib/systemd/systemd-journald >/tmp/journald-errors 2>&1 &
journal_pid=$!
trap 'kill "$journal_pid" 2>/dev/null || true' EXIT
sleep 1
echo fixture-journal-message | systemd-cat -t runsecure-fixture
journalctl --sync
'''
            command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '0:0', '--tmpfs', '/run:rw,nosuid,nodev,noexec,size=32m', '--tmpfs', '/var/log:rw,nosuid,nodev,noexec,size=32m', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m', '-v', volume+':/run/log/journal:rw', '--entrypoint', '/bin/sh', producer, '-ec', script]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, result.returncode, result.stderr)
            command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '0:0', '-v', volume+':/fixture-journal:ro', '--entrypoint', '/usr/bin/journalctl', NODE_IMAGE, '--directory=/fixture-journal', '--no-pager', '-o', 'json', '-t', 'runsecure-fixture']
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('"MESSAGE":"fixture-journal-message"', result.stdout)
            self.assertIn('"SYSLOG_IDENTIFIER":"runsecure-fixture"', result.stdout)
        finally:
            subprocess.run(['docker', 'volume', 'rm', volume], check=True, capture_output=True)
            if built:
                subprocess.run(['docker', 'image', 'rm', producer], capture_output=True)


if __name__=='__main__':
    unittest.main()
