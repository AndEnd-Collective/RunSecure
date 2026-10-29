#!/usr/bin/env python3
"""Actual collector -> fake CWL -> actual Lambda -> external object receiver.

This is a protocol fixture, not AWS IAM/S3/KMS acceptance. Uses only loopback,
synthetic credentials and synthetic records. No private source is copied here.
Set COLLECTOR_BINARY to the assembled pinned distribution before running.
"""
import base64
import contextlib
import gzip
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import threading
import unittest
import urllib.request

import test_distribution

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('archive_normalizer', ROOT/'examples/eks-bottlerocket/archive/normalizer.py')
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


class ObjectReceiver(http.server.BaseHTTPRequestHandler):
    objects = {}
    def log_message(self, *_):
        pass
    def do_PUT(self):
        if self.path != '/archive/fixture.ndjson.gz':
            self.send_error(403)
            return
        body = self.rfile.read(int(self.headers['Content-Length']))
        type(self).objects[self.path] = body
        self.send_response(200)
        self.end_headers()
    def do_GET(self):
        if self.path not in type(self).objects:
            self.send_error(404)
            return
        body = type(self).objects[self.path]
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(test_distribution.BINARY, 'Set COLLECTOR_BINARY; this test must use the assembled Cornerstone distribution')
class ExternalArchivePath(unittest.TestCase):
    def test_actual_records_reach_external_archive_with_identity_and_redaction(self):
        # Establish real output rather than hand-crafting what a collector might
        # emit. The component test also verifies actual schema/signature stages.
        case = test_distribution.DistributionFixture('test_cri_origin_adapter_private_validation_cwl_and_redaction')
        case.test_cri_origin_adapter_private_validation_cwl_and_redaction()
        records = test_distribution.CWL.records
        self.assertEqual(5, len(records))
        envelope = {'owner': '123456789012', 'messageType': 'DATA_MESSAGE',
                    'logGroup': '/runsecure/fixture/telemetry', 'logStream': 'collector-gateway',
                    'logEvents': [{'id': str(index), 'timestamp': 1793257200000,
                                   'message': json.dumps(record)} for index, record in enumerate(records)]}
        encoded = base64.b64encode(gzip.compress(json.dumps(envelope).encode())).decode()
        previous = {key: os.environ.get(key) for key in ['EXPECTED_ACCOUNT_ID', 'SOURCE_GROUPS_JSON', 'ARCHIVE_NAME']}
        os.environ.update(EXPECTED_ACCOUNT_ID='123456789012', SOURCE_GROUPS_JSON=json.dumps({'/runsecure/fixture/telemetry': 'collector'}), ARCHIVE_NAME='fixture')
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                response = normalizer.handler({'records': [{'recordId': 'fixture', 'data': encoded}]}, None)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual('Ok', response['records'][0]['result'])
        archive = base64.b64decode(response['records'][0]['data'])
        receiver = http.server.HTTPServer(('127.0.0.1', 0), ObjectReceiver)
        ObjectReceiver.objects = {}
        thread = threading.Thread(target=receiver.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{receiver.server_port}/archive/fixture.ndjson.gz'
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=gzip.compress(archive), method='PUT')) as result:
                self.assertEqual(200, result.status)
            with urllib.request.urlopen(url) as result:
                readback = gzip.decompress(result.read())
        finally:
            receiver.shutdown()
            receiver.server_close()
            thread.join(timeout=2)
        self.assertEqual(archive, readback)
        entries = [json.loads(line) for line in readback.splitlines()]
        self.assertEqual(5, len(entries))
        self.assertTrue(all(entry['origin']['account_id']=='123456789012' and entry['validation_status']=='not_validated' for entry in entries))
        self.assertNotIn('super-secret-fixture', readback.decode())
        self.assertNotIn('ghp_fixtureTokenWhichMustNeverEscape1234567890', readback.decode())
        attrs = [json.loads(entry['message'])['attributes'] for entry in entries]
        typed = [item for item in attrs if item['cornerstone.event.signature']=='runsecure-orchestrator-v1']
        captures = [item for item in attrs if item['cornerstone.event.signature']=='runsecure-telemetry-v1']
        self.assertEqual(3, len(typed))
        self.assertEqual(1, sum(item['cornerstone.validation.signature.validated'] for item in typed))
        self.assertEqual(2, len(captures))
        self.assertTrue(all(item['cornerstone.validation.schema.validated'] and item['cornerstone.validation.signature.validated'] for item in captures))


if __name__ == '__main__':
    unittest.main()
