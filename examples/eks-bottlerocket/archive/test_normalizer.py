"""Real compressed CloudWatch envelopes: no network mocks or raw-log fixtures."""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name('normalizer.py')
GROUPS = {'/runsecure/example/telemetry': 'collector', '/aws/eks/example/cluster': 'eks-control-plane'}

def record(message='hello', **updates):
    envelope = {'owner': '123456789012', 'logGroup': '/runsecure/example/telemetry',
                'logStream': 'node-1', 'messageType': 'DATA_MESSAGE',
                'logEvents': [{'id': 'event-1', 'timestamp': 1000, 'message': message}]}
    envelope.update(updates)
    return {'recordId': 'record-1', 'data': base64.b64encode(gzip.compress(json.dumps(envelope).encode())).decode()}

class NormalizerTests(unittest.TestCase):
    def setUp(self):
        if not MODULE.exists():
            self.fail('Normalizer implementation is missing: compressed-envelope contract cannot run')
        spec = importlib.util.spec_from_file_location('normalizer', MODULE)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.env = patch.dict(os.environ, {'EXPECTED_ACCOUNT_ID': '123456789012',
            'SOURCE_GROUPS_JSON': json.dumps(GROUPS), 'ARCHIVE_NAME': 'fixture'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def invoke(self, records):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.mod.handler({'records': records}, None)
        return result['records'], output.getvalue()

    def test_each_line_has_separate_ndjson_and_non_overridable_origin(self):
        result, _ = self.invoke([record('first\n{"validation_status":"validated","owner":"evil"}')])
        self.assertEqual(result[0]['result'], 'Ok')
        lines = [json.loads(line) for line in base64.b64decode(result[0]['data']).splitlines()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]['message'], 'first')
        self.assertEqual(lines[1]['validation_status'], 'not_validated')
        self.assertEqual(lines[1]['origin'], {'account_id': '123456789012', 'log_group': '/runsecure/example/telemetry',
            'log_stream': 'node-1', 'source_type': 'collector', 'transport': 'aws-cloudwatch-logs'})
        self.assertEqual(lines[1]['line_index'], 1)
        self.assertEqual(lines[0]['event_id'], 'event-1')

    def test_known_secrets_are_redacted_and_never_printed(self):
        secret = 'ghp_' + 'A' * 36
        message = 'token="opaque-value" Authorization: Bearer private-value\n' + secret + '\n-----BEGIN PRIVATE KEY-----\nKEYMATERIAL\n-----END PRIVATE KEY-----'
        result, logs = self.invoke([record(message)])
        decoded = base64.b64decode(result[0]['data']).decode()
        for value in ['opaque-value', 'private-value', secret, 'KEYMATERIAL']:
            self.assertNotIn(value, decoded)
            self.assertNotIn(value, logs)
        self.assertIn('[REDACTED]', decoded)

    def test_unknown_group_wrong_owner_and_malformed_records_fail_without_archive_fallback(self):
        for item in [record(logGroup='/unapproved'), record(owner='999999999999'), {'recordId': 'bad', 'data': 'not-base64'}]:
            with self.subTest(item=item['recordId']):
                result, logs = self.invoke([item])
                self.assertEqual(result[0]['result'], 'ProcessingFailed')
                self.assertEqual(result[0]['data'], item['data'])  # Firehose error channel only.
                self.assertIn('ProcessingFailures', logs)
                self.assertNotIn(item['data'], logs)

    def test_decompression_bomb_and_event_count_are_bounded(self):
        for item in [record('x' * (3 * 1024 * 1024)), record(logEvents=[{'id': str(i), 'timestamp': 1, 'message': 'x'} for i in range(5001)])]:
            result, _ = self.invoke([item])
            self.assertEqual(result[0]['result'], 'ProcessingFailed')

    def test_control_message_is_explicitly_dropped_not_archived(self):
        result, logs = self.invoke([record(messageType='CONTROL_MESSAGE', logEvents=[])])
        self.assertEqual(result[0]['result'], 'Dropped')
        self.assertIn('ControlMessages', logs)

    def test_invalid_event_and_unknown_source_type_fail(self):
        result, _ = self.invoke([record(logEvents=[{'id': 'event', 'timestamp': True, 'message': 'x'}])])
        self.assertEqual(result[0]['result'], 'ProcessingFailed')
        os.environ['SOURCE_GROUPS_JSON'] = json.dumps({'/runsecure/example/telemetry': 'validated-cornerstone'})
        with self.assertRaises(ValueError):
            self.invoke([record()])

    def test_batch_expansion_never_exceeds_synchronous_response_limit(self):
        items = [dict(record('x' * 30000), recordId=f'record-{i}') for i in range(200)]
        result, _ = self.invoke(items)
        self.assertLess(len(json.dumps({'records': result}).encode()), 6 * 1024 * 1024)
        self.assertTrue(any(item['result'] == 'ProcessingFailed' for item in result))

    def test_stream_metadata_secrets_are_redacted(self):
        result, _ = self.invoke([record(logStream='ghp_' + 'A' * 36)])
        self.assertNotIn('ghp_', base64.b64decode(result[0]['data']).decode())

    def test_basic_auth_signed_urls_and_encoded_jit_are_redacted_in_real_envelopes(self):
        cases = [
            ('Authorization: Basic c3ludGhldGljLXNlY3JldA==', 'c3ludGhldGljLXNlY3JldA=='),
            ('https://example.invalid/path?X-Amz-Signature=synthetic-signed-value', 'synthetic-signed-value'),
            ('https://example.invalid/path?sig=synthetic-azure-value#fragment-secret', 'synthetic-azure-value'),
            ('{"JITConfigB64":"synthetic-jit-value"}', 'synthetic-jit-value'),
            ('{"encodedJITConfig":"synthetic-encoded-value"}', 'synthetic-encoded-value'),
        ]
        for message, secret in cases:
            with self.subTest(message_type=message.split(':', 1)[0]):
                result, logs = self.invoke([record(message)])
                self.assertEqual(result[0]['result'], 'Ok')
                payload = base64.b64decode(result[0]['data']).decode()
                self.assertNotIn(secret, payload)
                self.assertNotIn(secret, logs)
                self.assertNotIn('fragment-secret', payload)
                entry = json.loads(payload)
                self.assertEqual(entry['origin']['account_id'], '123456789012')
                self.assertEqual(entry['validation_status'], 'not_validated')
                if message.startswith('{'):
                    self.assertIsInstance(json.loads(entry['message']), dict)

    def test_nested_collector_json_remains_parseable_with_validation_metadata(self):
        event = {'event.signature': 'runsecure-telemetry-v1', 'event.details': {
            'message': 'password="synthetic-secret"', 'result': 'success'}}
        collector = {'body': json.dumps(event), 'attributes': {
            'cornerstone.event.details': event['event.details'],
            'cornerstone.validation.schema.validated': True}}
        result, _ = self.invoke([record(json.dumps(collector))])
        entry = json.loads(base64.b64decode(result[0]['data']))
        outer = json.loads(entry['message'])
        inner = json.loads(outer['body'])
        self.assertNotIn('synthetic-secret', json.dumps(outer))
        self.assertEqual('success', inner['event.details']['result'])
        self.assertIs(outer['attributes']['cornerstone.validation.schema.validated'], True)

    def test_prefixed_secret_keys_are_not_exempted_by_structured_redaction(self):
        for key in ['encodedJITConfigB64', 'api_token', 'RUNSECURE_GITHUB_TOKEN', 'web.context.headers.authorization']:
            with self.subTest(key=key):
                message = json.dumps({key: 'synthetic-opaque-sensitive-value',
                    'cornerstone.validation.signature.validated': True})
                result, _ = self.invoke([record(message)])
                entry = json.loads(base64.b64decode(result[0]['data']))
                decoded = json.loads(entry['message'])
                self.assertEqual('[REDACTED]', decoded[key])
                self.assertIs(decoded['cornerstone.validation.signature.validated'], True)

    def test_json_scalar_and_nested_scalar_escaping_remains_valid(self):
        scalar = json.dumps('token="synthetic-scalar-secret"')
        for message in [scalar, json.dumps({'body': scalar})]:
            result, _ = self.invoke([record(message)])
            entry = json.loads(base64.b64decode(result[0]['data']))
            value = json.loads(entry['message'])
            if isinstance(value, dict):
                value = json.loads(value['body'])
            self.assertIsInstance(value, str)
            self.assertNotIn('synthetic-scalar-secret', value)

if __name__ == '__main__':
    unittest.main()
