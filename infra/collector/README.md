# RunSecure archival collector

This is a build recipe and tested local candidate, not a published collector or
commissioned EKS deployment. See the [deployment and evidence contract](../../docs/cornerstone-logging-design.md).

The public recipe assembles Collector **0.158.0 / core 1.64.0** with the
separately authorized private Cornerstone checkout at
`490fc072c02d72a0dc62633d0c4f573b6707b4ef`. That checkout's Go module requires
this release line; its older 0.150 builder example is not the resolved version.
No private implementation is vendored here. The public adapter is under
`processor/`; it prepares canonical attributes before the Cornerstone enricher,
schema and signature processors. CloudWatch export keeps the full OTEL wrapper
and validation attributes (`raw_log: false`), with fixed group/stream settings.

Build outside the public checkout, with no credential build arguments:

```sh
CORNERSTONE_SOURCE=/absolute/path/to/authorized/private-checkout \
COLLECTOR_BUILD_DIR=/absolute/path/to/private-local-build-output \
  bash infra/collector/build.sh

# Optional unpublished Linux image; the named context contains only the module.
CORNERSTONE_SOURCE=/absolute/path/to/authorized/private-checkout \
COLLECTOR_BUILD_DIR=/absolute/path/to/private-local-build-output \
BUILD_IMAGE=1 COLLECTOR_IMAGE=runsecure-collector:local-test \
  bash infra/collector/build.sh
```

`build-info.txt` records the resolved modules. The Docker build supplies only the
private `otel-collector/` directory as `cornerstone-src`; the runtime image
contains the compiled binary and Debian's actual `journalctl`, with no private
source tree or Git credentials. Its Debian journal reader is tested against an
isolated systemd journal; compatibility with the selected Bottlerocket release,
its active journal directory, rotation, reboot and unit inventory remains a
target-cluster acceptance gate. Empty `nodeReader.journalUnits` captures all
units; a nonempty filter deliberately narrows coverage.

Local verification (Python requires PyYAML 6.0.3):

```sh
python3 infra/collector/sync-signatures.py --check
helm lint charts/runsecure-telemetry
python3 infra/collector/tests/test_chart.py
(cd infra/collector/tests/admission && go test ./...)
COLLECTOR_BINARY=/absolute/path/to/build/dist/runsecure-collector \
COLLECTOR_IMAGE=runsecure-collector:local-test \
  python3 -m unittest discover -s infra/collector/tests -p 'test_*.py'
```

Fixtures use loopback-only fake CloudWatch and archive endpoints, disposable
certificates and explicit nonfunctional AWS fixture credentials. They cover
actual CRI metadata extraction, producer spoofing, valid/invalid private
validation, redaction, mTLS rejection/acceptance and durable queue replay after
an outage/restart with the source removed. The Linux fixture has no network,
all capabilities dropped and a read-only root filesystem. None commissions EKS.

Node offsets and queues persist in `/var/lib/runsecure-telemetry`; the gateway
requires an encrypted persistent StorageClass and PVC. Filelog checkpoints can
contain raw fingerprint bytes before processor redaction: protect this local
state as sensitive, including backups. Finite queues can fill and source files
can rotate during outages; this is not a zero-loss promise. Collector diagnostics
use a separate persisted path/pipeline. Only that diagnostic transport's own
component errors are excluded from re-ingestion to break feedback; they remain
local and require queue/drop/disk/receiver-health monitoring and incident export.
