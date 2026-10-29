# Cornerstone collection and external EKS log archive

This is an implementation and an illustrative deployment contract, not a live
EKS delivery receipt. The new source is unreleased. Existing v2.2.1 images do
not acquire the new instrumentation merely by setting Helm values. Qualify
images built from the reviewed successor source before activation. The
[foundation guide](eks-guidebook.md) and its workload-egress prerequisites still
apply. No mesh or application-wide mTLS is introduced by this logging chart.

## Sources and trust

| Source | Collection and destination | Interpretation |
| --- | --- | --- |
| Orchestrator and socket proxy | Typed JSON on stdout (failure diagnostics on stderr), host-attributed CRI input, Cornerstone gateway, CloudWatch, transformed Firehose, S3 `archive/` | Existing signatures plus stable event-definition UUIDs; controller actor comes from Downward API/host metadata |
| Runner output, shell entrypoints, Squid/HAProxy/dnsmasq and platform containers | CRI file reader and same gateway/archive | Lower-trust capture envelope; JSON claiming to be a controller event stays untrusted content |
| Bottlerocket host/kubelet/containerd | Real journald receiver and `journalctl`; CNI host files where present | Host capture, with node identity; selected release/path/journal compatibility must be proven on the target |
| Collector internal diagnostics | Persistent local JSON file, separate diagnostic pipeline, same gateway archive | Self-transport errors are excluded from their own ingestion to prevent a feedback loop; retained locally and monitored separately |
| EKS API/audit/authenticator/controllerManager/scheduler | Existing EKS control-plane log group, AWS-native subscription, transformed Firehose | Verified AWS account/group origin; not asserted to be a validated Cornerstone producer |
| DNS, Network Firewall FLOW/ALERT, VPC flow | Explicit AWS log groups and subscriptions, transformed Firehose | DNS and network evidence; VPC `SKIPDATA` means incomplete coverage |
| Normalizer Lambda/main Firehose diagnostics | Separate subscription and no-transform Firehose, S3 `delivery-diagnostics/POSSIBLY-SENSITIVE/` | Raw compressed CloudWatch envelopes, potentially sensitive; no recursive diagnostic log sink |
| AWS management API audit | Optional dedicated CloudTrail, default off, S3 `cloudtrail/` with validation digests | Native CloudTrail format; existing organization trails must be assessed separately |

“Captured successfully” describes receipt of a message, never success of the
job or truth of its contents. Schema validity does not authenticate a workload.
Only configured controller/container/path tuples can preserve the two typed
RunSecure signatures. The adapter strips producer validation claims, maps
canonical keys to OTEL attributes and uses descendant context attributes to
avoid ambiguous parent/child representations. The pinned Cornerstone schema and
signature processors run adjacently in one process; persistence follows them.
The archive's outer `validation_status: not_validated` describes the AWS archive
wrapper. Inspect the serialized collector attributes for actual schema/signature
results; AWS-native sources have no such result.

## Isolation and credentials

`charts/runsecure-telemetry` is disabled by default. The gateway is a singleton
StatefulSet in `runsecure-observability`, with PSS Restricted, non-root UID,
read-only root, all capabilities dropped and an encrypted durable PVC. It has
no Kubernetes API token/RBAC, host mount or Docker socket. This is durable
single-instance recovery, not HA or a zero-loss guarantee.

The node DaemonSet lives in the separate `runsecure-observability-node`
namespace because host-path collection cannot satisfy PSS Restricted. A
fail-closed admission policy restricts the exception to the exact reviewed
image, container, arguments, identity, mounts and security context. It checks
init and ephemeral containers too. It permits only read-only log/journal paths
and one explicit writable cursor/queue directory. No host network/PID/IPC,
privileged container, capabilities, Docker socket, host root, service-account
token or AWS role is added. Reading node logs nevertheless exposes sensitive
host information: limit namespace administration and protect the node itself.

Agents authenticate to the gateway with a dedicated client-certificate trust
root over TLS 1.3. The gateway has a server certificate for its service DNS name.
Supply existing Secrets containing `tls.crt`, `tls.key`, `ca.crt` separately in
the two namespaces; never place keys in values or Terraform state. Restrict
Secret readers, define expiry alerts, rotate with overlapping trusted CA
material and staged restarts, then remove the old trust root after validation.
A valid agent certificate authorizes the host-log trust boundary; a compromised
node/collector can falsify records. Namespace selectors and mTLS exclude direct
job ingestion, but are not defenses against a compromised cluster administrator.

Default-deny policies permit agent-to-gateway OTLP, exact controlled DNS,
gateway-to-private Logs endpoint /32s on 443, and the Pod Identity agent's exact
link-local address/port. Monitoring ingress needs explicit namespace and Pod
selectors. Jobs receive none of these telemetry exceptions. Private AWS
platform delivery does not add AWS internet suffixes or S3 access to job egress.

Only the gateway's exact service account gets Pod Identity for two named Logs
write operations on one log group. The node reader has no AWS credentials; the
gateway has no S3, Firehose or KMS permission. Dedicated AWS service roles move
records to fixed archive prefixes. Named actions are used throughout. The few
global resource forms have specific meanings: KMS key-policy `Resource` denotes
that key; VPC-flow `DescribeLogGroups` cannot be resource-scoped and is
region-bound; log-stream/object suffixes select children of exact resources.
No wildcard action or general runner cloud authority is introduced.

## Build and staged deployment

The separately authorized Cornerstone source is pinned at
`490fc072c02d72a0dc62633d0c4f573b6707b4ef`. Public RunSecure contains its
integration recipe, not its private implementation. `infra/collector/build.sh`
requires a clean checkout at that revision and a build directory outside this
repository. The supported recipe uses OCB/core release 0.164.0, core modules 1.70.0
and contrib modules 0.164.1, following the current official distribution. The
pinned Cornerstone source is qualified on this coherent graph without vendoring
or changing its private implementation. Do not substitute a stock collector
lacking the Cornerstone processors or the public normalization adapter.

Two image targets share the custom static binary. The non-root gateway is a
scratch image containing only the binary and a qualified CA bundle. The node
reader separately carries Debian's real `journalctl` and native package
inventory. Only the node reader needs that native surface; its remaining
advisories must be assessed independently of the minimal gateway scan.

```sh
CORNERSTONE_SOURCE=/approved/private/checkout \
COLLECTOR_BUILD_DIR=/approved/local/build \
  bash infra/collector/build.sh
# Optional local pair build: also set BUILD_IMAGE=1,
# COLLECTOR_GATEWAY_IMAGE and COLLECTOR_NODE_IMAGE to distinct local tags.
# Publication is a separate reviewed step; no token/private checkout is committed.
```

Record resolved modules, source revision, each image manifest digest, SBOM and
scan results. Scan both final architecture-specific images with the normal
high/critical gate; do not suppress the gate. Mirror approved role images to the private registry
reachable by the cluster and include its exact repository ARN in the reviewed
`pull_repository_arns` input. Public CI does not gain access to the private
Cornerstone repository, and this change does not add collector publication to
the automatic public runner-image release matrix. A local image config ID is
not a manifest digest.

1. Review a saved Terraform plan for the foundation and archive additions.
   The example creates a dedicated account/region-specific bucket, CMK, fixed
   log groups, subscriptions, Firehose/Lambda roles, alarms and Pod Identity.
   Supply the existing alarm destination or explicitly accept that alarms have
   no notification action. This documentation does not authorize an apply.
2. Qualify strict CNI enforcement on Secret-owned runner Pods, DNS and private
   endpoints. Use `telemetry_logs_endpoint_cidrs`, `telemetry_context`, log-group
   and role outputs. Refresh endpoint peers after ENI replacement. Supply a
   reviewed encrypted StorageClass and working CSI installation; this example
   does not silently create a broadly privileged storage driver.
3. Supply distinct `gateway.image` and `nodeReader.image` private manifest
   references, durable storage, TLS Secrets and
   cloud/cluster context in a private operator values file. The supplied render
   fixture is deliberately unable to start workloads. The unpublished prior
   single `image` value is rejected; migrate it to the two qualified role refs.
   Review the trusted source
   tuple against the actual controller Pod/container names. Add socket-proxy
   trust only on a deployment that actually runs that component.
4. Install the guard-only phase (`nodeReader.installGuardOnly=true`,
   `nodeReader.activateGuardNamespace=false`) with the node namespace still
   PSS Restricted.
   Verify the active, compiled exact guard, then use the separate guarded
   namespace-activation phase (`installGuardOnly=true`,
   `activateGuardNamespace=true`) to change only that namespace to PSS Privileged;
   no node workload starts in either phase. Then verify live admission using
   `infra/collector/preflight-admission.py`. A denied dry-run must identify the
   expected policy; an unrelated denial is not proof. Read back the exact policy
   and binding. The normal chart upgrade checks live guard contents before it
   can render node workloads. Restrict who can alter the policy, namespace,
   DaemonSet and Secrets.
5. Upgrade the same release with `nodeReader.installGuardOnly=false` and
   `nodeReader.activateGuardNamespace=false`. Keep the
   gateway singleton. Check PVC binding, readiness, reader placement on every
   intended node and coverage of rotated CRI/journal files. No Terraform or Helm
   command in the test suite applies these resources to EKS.
6. Complete the acceptance checklist below before enabling production jobs.

## Redaction, retention and operational recovery

Typed producers avoid raw auth/config/request payloads and redact known secret
keys and formats. Node ingestion redacts before its persistent sending queue;
gateway normalization repeats redaction. This is pattern-based protection, not
complete secret discovery. Unknown opaque secrets can still be logged by jobs.
Original CRI/journal files, receiver checkpoints (including file-content
fingerprint bytes) and collector diagnostic files exist before redaction;
protect their host/PVC access and retention. AWS-native groups also retain their
original messages before the Firehose processor's best-effort redaction.

Normal archive records are newline-delimited JSON, then gzip compressed. Source
account and exact log-group allowlists are enforced by the bounded transformer.
Malformed, excessive-expansion and oversized invocations fail into the encrypted,
restricted `processing-errors/POSSIBLY-SENSITIVE/` prefix; they are never
presented as clean successful records. Diagnostic archives and optional
CloudTrail use their explicitly different native formats. Error and diagnostic
prefixes may contain unredacted originals and need narrower human-reader access.

The bucket blocks public access, enforces TLS and KMS configuration, versions
objects and uses finite lifecycle rules. Current versions expire after the
configured number of days; noncurrent versions have their own retention period,
so total object retention can exceed that number. KMS destruction is prevented
in source and bucket force-destroy is off. This is not WORM/Object Lock; choose
separately reviewed retention/legal-hold requirements if needed. CloudWatch
source retention and service retry windows are independent and finite.

Persist reader offsets and both gateway/agent queues. Alert on refused records,
exporter failures, queue utilization/capacity, file-storage errors/free space,
restart/missing-node coverage, certificate expiry, subscription errors/throttling,
Lambda failures, rejected transforms, Firehose delivery/freshness and VPC
`SKIPDATA`. Configure external Prometheus scraping using the chart's explicit
monitoring selectors; the chart exposes metrics but does not install a monitoring
operator or receiver. Confirm actual metric names/dimensions with the pinned
binary and AWS before accepting alarms. Idle/missing data is not success: use
an independent periodic sentinel and check its arrival from outside the cluster.

On delivery failure, stop accepting more jobs if the measured retention budget
is threatened. Preserve offsets/PVCs and sensitive error objects, repair the
specific certificate/endpoint/permission/capacity problem and replay through a
reviewed tool with deduplication by event UUID/AWS event identity. Do not delete
state or widen egress as a recovery shortcut. Local self-transport errors remain
on disk and metrics because feeding them back into their failing exporter would
loop; collect/replay those files through a separate approved incident path.

Collector 0.164 rewrites filelog checkpoints in protobuf while retaining legacy
JSON read compatibility. Back up state and qualify rollback before assuming an
older binary can consume newly written checkpoints.

For upgrades, drain jobs, snapshot recovery state, verify chart/config and
processor/schema compatibility, change one pinned image at a time and repeat
negative security/delivery tests. Roll back to the last accepted digest/config
while preserving state; test queue-format downgrade compatibility first. Never
run two singleton controllers or two writers against the same queue/PVC. Version
rollbacks do not erase already archived invalid/sensitive records.

## Acceptance evidence and limits

Local checks exercise typed producers, hostile captures, real collector loading,
real journal input, fixed CloudWatch serialization and the real archive
transformer with an external local object receiver. TLS, queue restart and guard
checks must report their own results. Mocked Terraform plans prove source
contracts, not AWS service acceptance or effective live IAM. A green workflow is
not evidence of a live EKS deployment or clean vulnerability coverage.

Before commissioning, independently prove all of these on the selected EKS and
Bottlerocket releases: denied untrusted/missing-client ingestion; denied job
access to telemetry/IMDS/AWS endpoints; accepted agent mTLS; node log-path and
journal compatibility; Secret-owned Pod policy enforcement; all intended source
groups reaching S3; denied unrelated account/group and bucket/prefix access;
encryption and reader scope; real alarm notification; sentinel loss detection;
outage/restart/replay within disk budgets; certificate rotation; node replacement;
and absence of secret canaries in the normal archive. Preserve run receipts and
exact source/image/manifest digests. This topology does not establish a SLSA
level; see [the build/source assurance assessment](eks-slsa.md).

Official references last checked **2026-10-29 07:08 UTC**:
[CloudWatch subscription envelopes](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html),
[CloudWatch-to-Firehose compression](https://docs.aws.amazon.com/firehose/latest/dev/writing-with-cloudwatch-logs.html),
[Firehose IAM and destination access](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html),
[Pod Identity trust and isolation limits](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html).
