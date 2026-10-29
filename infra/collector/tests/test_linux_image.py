#!/usr/bin/env python3
"""Validate both deployed configs and a real isolated Linux journal fixture."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[3]
IMAGE = os.environ.get('COLLECTOR_IMAGE', '')


@unittest.skipUnless(IMAGE, 'Set COLLECTOR_IMAGE to the locally built, unpublished image')
class LinuxImage(unittest.TestCase):
    def test_actual_agent_and_gateway_configs(self):
        render = subprocess.check_output(['helm', 'template', 'telemetry', str(ROOT/'charts/runsecure-telemetry'), '-f', str(Path(__file__).parent/'values.render.yaml')], text=True)
        # Colima shares /Users; macOS /var/folders temporary directories are not
        # necessarily visible to its Docker daemon.
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
                user = '0:0' if name.endswith('node') else '10001:10001'
                command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', user, '-e', 'NODE_NAME=fixture-node', '-v', str(tmp)+':/fixture:ro', '-v', str(tmp/'events')+':/etc/otel-events:ro', '-v', str(state)+':/var/lib/otel:rw', IMAGE, 'validate', '--config=/fixture/'+config.name]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, result.returncode, name+': '+result.stderr)

    def test_journalctl_reads_real_journal_without_capabilities(self):
        # This validates the packaged systemd journal format only. The
        # selected Bottlerocket journal and unit inventory remain a live gate.
        script = '''mkdir -p /run/log/journal /run/systemd/journal
/lib/systemd/systemd-journald >/tmp/journald-errors 2>&1 &
journal_pid=$!
trap 'kill "$journal_pid" 2>/dev/null || true' EXIT
sleep 1
echo fixture-journal-message | systemd-cat -t runsecure-fixture
journalctl --sync
journalctl --directory=/run/log/journal --no-pager -o json -t runsecure-fixture
'''
        command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '0:0', '--tmpfs', '/run:rw,nosuid,nodev,noexec,size=32m', '--tmpfs', '/var/log:rw,nosuid,nodev,noexec,size=32m', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m', '--entrypoint', '/bin/sh', IMAGE, '-ec', script]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('"MESSAGE":"fixture-journal-message"', result.stdout)
        self.assertIn('"SYSLOG_IDENTIFIER":"runsecure-fixture"', result.stdout)


if __name__=='__main__':
    unittest.main()
