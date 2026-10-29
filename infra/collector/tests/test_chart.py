#!/usr/bin/env python3
"""Render contracts, including deliberately rejected unsafe configurations."""
import copy
import ipaddress
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / 'charts/runsecure-telemetry'
FIXTURE = yaml.safe_load((Path(__file__).parent / 'values.render.yaml').read_text())


def render(values=None, success=True):
    with tempfile.TemporaryDirectory() as tmp:
        command = ['helm', 'template', 'telemetry', str(CHART)]
        if values is not None:
            path = Path(tmp) / 'values.yaml'
            path.write_text(yaml.safe_dump(values))
            command += ['-f', str(path)]
        result = subprocess.run(command, capture_output=True, text=True)
        if success:
            assert result.returncode == 0, result.stderr
            return [d for d in yaml.safe_load_all(result.stdout) if d]
        assert result.returncode != 0, result.stdout
        return result.stderr


class ChartContract(unittest.TestCase):
    def test_disabled_default_emits_nothing(self):
        self.assertEqual([], render())

    def test_missing_required_and_unknown_values_rejected(self):
        self.assertIn('accountId', render({'enabled': True}, False))
        bad = copy.deepcopy(FIXTURE)
        bad['aws']['accessKey'] = 'never-supported'
        self.assertIn('accessKey', render(bad, False))
        for stream in ['{PodName}', 'job/{TaskId}', 'malicious:producer']:
            bad = copy.deepcopy(FIXTURE)
            bad['aws']['logStreamPrefix'] = stream
            self.assertIn('fixed', render(bad, False))

    def test_live_guard_required(self):
        bad = copy.deepcopy(FIXTURE)
        bad['renderOnly'] = False
        self.assertIn('live readback required', render(bad, False))

    def test_guard_phase_has_no_workload_or_gateway_identity(self):
        values = copy.deepcopy(FIXTURE)
        values['nodeReader'] = {'installGuardOnly': True}
        docs = render(values)
        self.assertFalse(any(d['kind'] in ['DaemonSet', 'StatefulSet'] for d in docs))
        accounts = [d for d in docs if d['kind']=='ServiceAccount']
        self.assertEqual(['runsecure-telemetry-node'], [d['metadata']['name'] for d in accounts])
        self.assertFalse(accounts[0]['automountServiceAccountToken'])
        node_namespace = next(d for d in docs if d['kind']=='Namespace' and d['metadata']['name']=='runsecure-observability-node')
        self.assertEqual('restricted', node_namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'])
        policy = next(d for d in docs if d['kind'] == 'ValidatingAdmissionPolicy')
        self.assertEqual('Fail', policy['spec']['failurePolicy'])
        self.assertEqual("request.namespace == 'runsecure-observability-node'", policy['spec']['matchConditions'][0]['expression'])
        assertions = '\n'.join(v['expression'] for v in policy['spec']['validations'])
        for requirement in ['ephemeralContainers', 'initContainers', 'hostNetwork', 'hostPID', 'hostIPC', 'readOnlyRootFilesystem', 'capabilities.drop', 'mountPropagation', 'subPath', '/var/lib/runsecure-telemetry', '/var/log/pods', 'envFrom', 'lifecycle']:
            self.assertIn(requirement, assertions)
        binding = next(d for d in docs if d['kind'] == 'ValidatingAdmissionPolicyBinding')
        self.assertEqual(['Deny'], binding['spec']['validationActions'])

    def test_namespace_activation_is_separate_and_has_no_workloads(self):
        values=copy.deepcopy(FIXTURE)
        values['nodeReader']={'installGuardOnly':True,'activateGuardNamespace':True}
        docs=render(values)
        self.assertFalse(any(d['kind'] in ['DaemonSet','StatefulSet'] for d in docs))
        self.assertFalse(any(d['kind']=='ServiceAccount' and d['metadata']['name']=='runsecure-telemetry-gateway' for d in docs))
        namespace=next(d for d in docs if d['kind']=='Namespace' and d['metadata']['name']=='runsecure-observability-node')
        self.assertEqual('restricted',namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'])
        values['renderOnly']=False
        self.assertIn('live readback required',render(values,False))

    def test_workload_isolation_and_render_only_fail_closed(self):
        docs = render(FIXTURE)
        namespaces=[d for d in docs if d['kind']=='Namespace']
        self.assertTrue(all(d['metadata']['labels']['pod-security.kubernetes.io/enforce']=='restricted' for d in namespaces))
        self.assertFalse(any(d['kind'] in ['Role', 'RoleBinding', 'ClusterRole', 'Secret'] for d in docs))
        for resource in [d for d in docs if d['kind'] in ['DaemonSet', 'StatefulSet']]:
            pod = resource['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertFalse(pod['hostNetwork'])
            self.assertEqual('never', pod['nodeSelector']['runsecure.io/telemetry-render-only'])
            self.assertEqual(['/bin/false'], pod['initContainers'][0]['command'])
            container = pod['containers'][0]
            self.assertTrue(container['image'].endswith('@'+FIXTURE['image']['digest']))
            self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
            self.assertFalse(container['securityContext']['privileged'])
            self.assertEqual(['ALL'], container['securityContext']['capabilities']['drop'])
            if resource['kind'] == 'StatefulSet':
                self.assertEqual('runsecure-telemetry-gateway', pod['serviceAccountName'])
                self.assertFalse(any('hostPath' in v for v in pod['volumes']))
                self.assertEqual('fixture-encrypted-gp3', resource['spec']['volumeClaimTemplates'][0]['spec']['storageClassName'])
            else:
                host_paths = {v['name']: v['hostPath']['path'] for v in pod['volumes'] if 'hostPath' in v}
                self.assertEqual('/var/lib/runsecure-telemetry', host_paths.pop('state'))
                mounts = {m['name']: m for m in container['volumeMounts']}
                self.assertTrue(all(mounts[name]['readOnly'] for name in host_paths))

    def test_configs_persist_offsets_queues_and_bound_destination(self):
        docs = render(FIXTURE)
        configs = {d['metadata']['name']: yaml.safe_load(d['data']['config.yaml']) for d in docs if d['kind'] == 'ConfigMap' and 'config.yaml' in d['data']}
        agent = configs['runsecure-telemetry-node']
        gateway = configs['runsecure-telemetry-gateway']
        for receiver in agent['receivers'].values():
            self.assertEqual('file_storage', receiver['storage'])
            self.assertTrue(receiver['retry_on_failure']['enabled'])
        self.assertEqual('/usr/bin/journalctl', agent['receivers']['journald']['journalctl_path'])
        self.assertLess(agent['exporters']['otlp']['sending_queue']['batch']['max_size'],4*1024*1024)
        self.assertNotIn('k8sattributes', agent['processors'])
        for cfg, exporter in [(agent, 'otlp'), (gateway, 'awscloudwatchlogs')]:
            output = cfg['exporters'][exporter]
            self.assertEqual('file_storage', output['sending_queue']['storage'])
            self.assertTrue(output['sending_queue']['block_on_overflow'])
            self.assertEqual('0s', output['retry_on_failure']['max_elapsed_time'])
        aws = gateway['exporters']['awscloudwatchlogs']
        self.assertEqual('/runsecure/fixture/telemetry', aws['log_group_name'])
        self.assertEqual('collector-gateway', aws['log_stream_name'])
        self.assertFalse(aws['raw_log'])
        stages = gateway['service']['pipelines']['logs']['processors']
        self.assertEqual(['runsecure_normalize', 'cornerstone_enricher', 'cornerstone_schema', 'cornerstone_validator'], stages[2:])
        tls = gateway['receivers']['otlp']['protocols']['grpc']['tls']
        self.assertEqual('/etc/otel-tls/ca.crt', tls['client_ca_file'])
        self.assertEqual('1.3', tls['min_version'])
        self.assertEqual('pass', gateway['processors']['cornerstone_schema']['validation']['on_invalid'])

    def test_network_policies_do_not_grant_jobs_ingress_or_cloud(self):
        docs = render(FIXTURE)
        policies = {d['metadata']['name']: d for d in docs if d['kind'] == 'NetworkPolicy' and d['metadata']['name'] != 'default-deny-all'}
        gateway = policies['runsecure-telemetry-gateway']['spec']
        peer = gateway['ingress'][0]['from'][0]
        self.assertEqual('runsecure-observability-node', peer['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'])
        self.assertEqual([{'protocol': 'TCP', 'port': 4317}], gateway['ingress'][0]['ports'])
        self.assertEqual(FIXTURE['aws']['logsEndpointIPs'], [p['ipBlock']['cidr'] for p in gateway['egress'][0]['to']])
        node = policies['runsecure-telemetry-node']['spec']
        self.assertEqual(2, len(node['egress']))
        self.assertNotIn('169.254.170.23', yaml.safe_dump(node))
        self.assertNotIn('0.0.0.0/0', yaml.safe_dump(policies))
        for address in FIXTURE['aws']['logsEndpointIPs']:
            self.assertTrue(ipaddress.ip_network(address).is_private)

    def test_signature_snapshot_matches_public_source(self):
        subprocess.run(['python3', str(ROOT/'infra/collector/sync-signatures.py'), '--check'], check=True)


if __name__ == '__main__':
    unittest.main()
