# RunSecure archival collector

This is a build recipe and tested local candidate, not a published collector or
commissioned EKS deployment. See the [deployment and evidence contract](../../docs/cornerstone-logging-design.md).

The public recipe assembles OCB/core Collector **0.164.0 / stable core modules 1.70.0**
and official-release contrib modules **0.164.1** with the
separately authorized private Cornerstone checkout at
`490fc072c02d72a0dc62633d0c4f573b6707b4ef`. The strict builder validates this
coherent release graph against the pinned private module; its older builder example is not the resolved version.
The only transitive override raises x/net to 0.62.0 for GO-2026-6860/6866;
it does not downgrade the Collector or its coupled SDK modules. See the
[exact qualification and unresolved scan results](../../docs/cornerstone-logging-verification.md).
No private implementation is vendored here. The public adapter is under
`processor/`; it prepares canonical attributes before the Cornerstone enricher,
schema and signature processors. CloudWatch export keeps the full OTEL wrapper
and validation attributes (`raw_log: false`), with fixed group/stream settings.

Build outside the public checkout, with no credential build arguments:

```sh
CORNERSTONE_SOURCE=/absolute/path/to/authorized/private-checkout \
COLLECTOR_BUILD_DIR=/absolute/path/to/private-local-build-output \
  bash infra/collector/build.sh

# Optional unpublished Linux role images; named context contains only the module.
CORNERSTONE_SOURCE=/absolute/path/to/authorized/private-checkout \
COLLECTOR_BUILD_DIR=/absolute/path/to/private-local-build-output \
BUILD_IMAGE=1 \
COLLECTOR_GATEWAY_IMAGE=runsecure-collector-gateway:local-test \
COLLECTOR_NODE_IMAGE=runsecure-collector-node:local-test \
  bash infra/collector/build.sh
```

The role tags must differ. The retired `COLLECTOR_IMAGE` build variable is
rejected. In chart values, set `gateway.image.repository` / `.digest` and
`nodeReader.image.repository` / `.digest` to separately verified manifest refs;
the old top-level `image` field is rejected and role digests must differ. Never
substitute the journal-capable node image for the gateway. Both artifacts need
separate SBOMs and vulnerability scans, including the node's native inventory.
A minimal gateway does not resolve any advisories remaining in the node runtime.

`build-info.txt` records the resolved modules. The Docker build supplies only the
private `otel-collector/` directory as `cornerstone-src`. The `gateway` target
contains only the custom static binary and the CA certificate bundle in scratch,
running as UID/GID 10001, without a shell, journalctl, package manager or native
runtime. The CA stage requires Debian's `20250419+deb13u1` security backport
or newer; the exported gateway bundle is checked for the distrusted emSign ECC
Root CA G3 / Comodo AAA roots' absence and Amazon Root CA 1's presence. See the
[Debian CA changelog](https://metadata.ftp-master.debian.org/changelogs//main/c/ca-certificates/ca-certificates_20250419%2Bdeb13u1_changelog).
The `node` target retains Debian trixie's actual `journalctl`, its
packaged native runtime and package inventory; apt upgrades remain required.
Both use the same custom binary and contain no private source or Git credentials.
The node reader is tested against a separate producer's real systemd journal,
mounted read-only with all capabilities dropped; compatibility with the selected
Bottlerocket release, its active journal directory, rotation, reboot and unit
inventory remains a
target-cluster acceptance gate. Empty `nodeReader.journalUnits` captures all
units; a nonempty filter deliberately narrows coverage.

Local verification (Python requires PyYAML 6.0.3):

```sh
python3 infra/collector/sync-signatures.py --check
helm lint charts/runsecure-telemetry
python3 infra/collector/tests/test_chart.py
(cd infra/collector/tests/admission && go test ./...)
COLLECTOR_BINARY=/absolute/path/to/build/dist/runsecure-collector \
COLLECTOR_GATEWAY_IMAGE=runsecure-collector-gateway:local-test \
COLLECTOR_NODE_IMAGE=runsecure-collector-node:local-test \
  python3 -m unittest discover -s infra/collector/tests -p 'test_*.py'
```

Fixtures use loopback-only fake CloudWatch and archive endpoints, disposable
certificates and explicit nonfunctional AWS fixture credentials. They cover
actual CRI metadata extraction, producer spoofing, valid/invalid private
validation, redaction, mTLS rejection/acceptance and durable queue replay after
an outage/restart with the source removed. Linux runtime fixtures have no network,
all capabilities dropped and a read-only root filesystem. The journal fixture builds a disposable pinned Debian
producer image; `COLLECTOR_JOURNAL_PRODUCER_IMAGE` may select an already built
fixture producer to avoid rebuilding it. It never layers tools onto a terminal
collector image. None commissions EKS.

Node offsets and queues persist in `/var/lib/runsecure-telemetry`; the gateway
requires an encrypted persistent StorageClass and PVC. Filelog checkpoints can
contain raw fingerprint bytes before processor redaction: protect this local
state as sensitive, including backups. Finite queues can fill and source files
can rotate during outages; this is not a zero-loss promise. Collector diagnostics
use a separate persisted path/pipeline. Only that diagnostic transport's own
component errors are excluded from re-ingestion to break feedback; they remain
local and require queue/drop/disk/receiver-health monitoring and incident export.
