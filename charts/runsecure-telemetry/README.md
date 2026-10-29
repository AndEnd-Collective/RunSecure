# RunSecure telemetry Helm chart

Default `enabled: false` emits no resources. Qualified installation uses the
[collector build](../../infra/collector/README.md) and
[deployment contract](../../docs/cornerstone-logging-design.md).

The fixed gateway identity is
`runsecure-observability/runsecure-telemetry-gateway`; only it receives a
CloudWatch Logs write Pod Identity association. Node readers run separately in
`runsecure-observability-node`, without Kubernetes API credentials or AWS roles.
They send mTLS OTLP gRPC to
`runsecure-telemetry-gateway.runsecure-observability.svc:4317`. Pre-existing TLS
Secrets must contain `tls.crt`, `tls.key` and the appropriate `ca.crt`. Secret
material never belongs in values. Gateway private Logs endpoint IPv4 /32s, exact
DNS peers, fixed archive group/prefix, reviewed AWS account/region and an
encrypted persistent StorageClass are required inputs.

The host reader needs root solely to read host-owned logs, with a read-only
rootfs, no capabilities, no privilege escalation and no host namespaces. Its
narrow hostPath exception has three stages:

1. `nodeReader.installGuardOnly: true`: install the Restricted namespace,
   credentialless node ServiceAccount and exact fail-closed admission guard.
2. Keep guard-only and set `nodeReader.activateGuardNamespace: true`: live
   lookup must verify exact guard/binding, current generation and successful
   CEL type checking before relaxing only this namespace. No workloads run.
3. Run `infra/collector/preflight-admission.py` with explicit reviewed context
   and values; then set guard-only/activation false to install the workloads.

Restrict writers to both namespaces. Guard readback does not establish zero API
cache propagation delay; the server-side positive/negative dry-runs remain
required. A populated ordinary offline `helm template` intentionally fails the
live guard check. `renderOnly: true` is only a test fixture: namespaces stay
Restricted, Pods have failing init containers and unsatisfiable placement. It
cannot commission collection and must not be used as deployment values.

Gateway ingress permits only node-reader namespace/Pod peers over 4317, plus
optional explicitly selected metrics scrapers. Gateway egress permits exact
private Logs endpoints, Pod Identity's link-local credential endpoint and exact
DNS peers. Jobs have no gateway rule. NetworkPolicy enforcement, host log path
and journal compatibility, Pod Identity, CSI, mTLS rotation, queue/disk pressure
alerts and archive readback all need independent acceptance on the real cluster.
