"""Bounded CloudWatch Logs -> Firehose NDJSON transformation.

ProcessingFailed intentionally sends the ORIGINAL record to Firehose's restricted,
KMS-encrypted error prefix. It is never a successful/raw archive fallback. No
payloads, envelope fields or exception contents are written to diagnostic logs.
Pattern redaction is best effort, not a complete secret detector.
"""
import base64
import binascii
import gzip
import io
import json
import os
import re
import time
import zlib
from urllib.parse import urlsplit, urlunsplit

MAX_COMPRESSED = 1024 * 1024
MAX_DECOMPRESSED = 2 * 1024 * 1024
MAX_EVENTS = 5000
MAX_LINES = 10000
MAX_OUTPUT = 2 * 1024 * 1024
MAX_RESPONSE = 5 * 1024 * 1024
SOURCE_TYPES = frozenset(('collector', 'eks-control-plane', 'route53-dns',
                         'network-firewall-flow', 'network-firewall-alert', 'vpc-flow'))
PEM = re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)')
TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b')
KEY_VALUE = re.compile(r'''(?i)(["']?(?:token|access[_-]?token|api[_-]?key|secret|secret[_-]?access[_-]?key|password|authorization|client[_-]?secret|private[_-]?key|(?:encoded[_-]?)?jit[_-]?config(?:[_-]?b64)?)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)''')
BEARER = re.compile(r'(?i)\b(?:Bearer|Basic)\s+[^\s"\',;]+')
URL_CREDENTIALS = re.compile(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@')
HTTP_URL = re.compile(r'''(?i)https?://[^\s"'<>]+''')


def redact_url(match):
    try:
        parsed = urlsplit(match.group(0))
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit('@', 1)[-1], parsed.path, '', ''))
    except ValueError:
        return '[REDACTED URL]'


def redact_plain(text):
    text = PEM.sub('[REDACTED]', text)
    text = TOKEN.sub('[REDACTED]', text)
    text = BEARER.sub('[REDACTED]', text)
    text = HTTP_URL.sub(redact_url, text)
    text = KEY_VALUE.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    return URL_CREDENTIALS.sub(r'\1[REDACTED]@', text)


SENSITIVE_KEY = re.compile(r'(?i)(?:(?:aws)?(?:accesskeyid|secretaccesskey|sessiontoken)|authorization|password|passwd|token|accesstoken|apikey|secret|clientsecret|credentials?|privatekey|jitconfig(?:b64)?|encodedjitconfig)$')


def redact(text, depth=0):
    """Preserve JSON syntax, including JSON-encoded bodies inside OTEL output.

    A quoted-assignment regex on serialized nested JSON can insert unescaped
    quotes. Parse structured content before scrubbing its strings and keys.
    Opaque text retains best-effort known-pattern redaction.
    """
    if depth > 32:
        return '[REDACTED DEPTH LIMIT]'
    try:
        value = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return redact_plain(text)
    def clean(item, level):
        if level > 32:
            return '[REDACTED DEPTH LIMIT]'
        if isinstance(item, dict):
            return {key: ('[REDACTED]' if SENSITIVE_KEY.search(re.sub(r'[^A-Za-z0-9]', '', key)) else clean(content, level + 1)) for key, content in item.items()}
        if isinstance(item, list):
            return [clean(content, level + 1) for content in item]
        if isinstance(item, str):
            return redact(item, level + 1)
        return item

    return json.dumps(clean(value, depth), separators=(',', ':'), ensure_ascii=True)


def configuration():
    account = os.environ['EXPECTED_ACCOUNT_ID']
    sources = json.loads(os.environ['SOURCE_GROUPS_JSON'])
    if not re.fullmatch(r'[0-9]{12}', account) or not isinstance(sources, dict) or not sources:
        raise ValueError('Invalid archive origin configuration')
    if any(not isinstance(group, str) or not group.startswith('/') or kind not in SOURCE_TYPES
           for group, kind in sources.items()):
        raise ValueError('Invalid archive source type')
    return account, sources


def transform(record, account, sources):
    data = record['data']
    if not isinstance(data, str) or len(data) > ((MAX_COMPRESSED + 2) // 3) * 4:
        raise ValueError('Compressed record too large')
    compressed = base64.b64decode(data, validate=True)
    if len(compressed) > MAX_COMPRESSED:
        raise ValueError('Compressed record too large')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as archive:
        raw = archive.read(MAX_DECOMPRESSED + 1)
    if len(raw) > MAX_DECOMPRESSED:
        raise ValueError('Envelope expansion exceeds limit')
    envelope = json.loads(raw)
    group = envelope['logGroup']
    stream = envelope['logStream']
    if envelope['owner'] != account or group not in sources or not isinstance(stream, str) or len(stream) > 512:
        raise ValueError('Unapproved origin')
    if envelope['messageType'] == 'CONTROL_MESSAGE':
        return 'Dropped', data
    events = envelope['logEvents']
    if envelope['messageType'] != 'DATA_MESSAGE' or not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
        raise ValueError('Invalid data envelope')
    origin = {'account_id': account, 'log_group': group, 'log_stream': redact(stream),
              'source_type': sources[group], 'transport': 'aws-cloudwatch-logs'}
    output = bytearray()
    count = 0
    for event in events:
        if (not isinstance(event, dict) or not isinstance(event.get('id'), str) or len(event['id']) > 256
                or type(event.get('timestamp')) is not int or event['timestamp'] < 0
                or not isinstance(event.get('message'), str)):
            raise ValueError('Invalid log event')
        # Redact before splitting so multiline PEM material cannot escape.
        for index, line in enumerate(redact(event['message']).splitlines() or ['']):
            count += 1
            if count > MAX_LINES:
                raise ValueError('Line count exceeds limit')
            entry = {'schema_version': 1, 'origin': origin, 'event_id': event['id'],
                     'timestamp_ms': event['timestamp'], 'line_index': index,
                     'validation_status': 'not_validated', 'message': line}
            output.extend(json.dumps(entry, separators=(',', ':'), ensure_ascii=True).encode() + b'\n')
            if len(output) > MAX_OUTPUT:
                raise ValueError('Expanded output exceeds limit')
    return 'Ok', base64.b64encode(output).decode()


def handler(event, context):
    account, sources = configuration()
    records = event['records']
    if not isinstance(records, list) or len(records) > 500 or len(json.dumps(event).encode()) > MAX_RESPONSE:
        raise ValueError('Oversized transform invocation')
    results = []
    failures = controls = 0
    budget = 0
    for record in records:
        # Firehose supplies these fields; malformed invocation is a batch failure.
        result = {'recordId': record['recordId'], 'result': 'ProcessingFailed', 'data': record['data']}
        try:
            status, data = transform(record, account, sources)
            size = len(json.dumps({'recordId': record['recordId'], 'result': status, 'data': data}).encode())
            if budget + size > MAX_RESPONSE - 131072:
                raise ValueError('Response budget exceeded')
            result.update(result=status, data=data)
        except (ValueError, KeyError, TypeError, OSError, EOFError, binascii.Error, RecursionError, zlib.error):
            failures += 1
        controls += result['result'] == 'Dropped'
        budget += len(json.dumps(result).encode()) + 1
        results.append(result)
    response = {'records': results}
    if len(json.dumps(response).encode()) > MAX_RESPONSE:
        # Never return a truncated response or silently drop data. Firehose retries
        # invocation failure and ultimately uses its encrypted error destination.
        raise ValueError('Response exceeds limit')
    print(json.dumps({'_aws': {'Timestamp': int(time.time() * 1000), 'CloudWatchMetrics': [
        {'Namespace': 'RunSecure/TelemetryArchive', 'Dimensions': [['ArchiveName']], 'Metrics': [
            {'Name': 'ProcessingFailures', 'Unit': 'Count'}, {'Name': 'ControlMessages', 'Unit': 'Count'}]}]},
        'ArchiveName': os.environ['ARCHIVE_NAME'], 'ProcessingFailures': failures, 'ControlMessages': controls}))
    return response
