# Cornerstone logging and the EKS archive

Implementation design; source and deployment templates only. No EKS, S3 or IAM
resources are commissioned by preparing this change. Existing EC2 runner
commissioning remains a separate reviewed change.

## Boundaries

RunSecure components emit canonical Cornerstone events with stable existing
orchestrator signatures, event-definition identity, explicit emitting Pod/cloud
context and bounded secret redaction. A single maintained standard-library Go
helper is mirrored deterministically into the existing isolated Go build
contexts. Its mirror check prevents drift without changing Docker build callers.

An authenticated node reader collects CRI container output, Bottlerocket journal
and CNI host logs. It attributes records from host-controlled paths and metadata,
not fields claimed inside application output. The gateway treats workload output
as untrusted captured data even when it looks like a controller event. The
normalizer removes producer-supplied validation annotations, makes canonical
attributes explicitly, and runs the actual Cornerstone schema/signature stages.
Schema validity is not proof that a workload's message is true or safe.

The gateway uses a minimal scratch/CA/static-binary image and runs in a
dedicated Restricted observability namespace. A separate
node-reader namespace needs narrowly guarded host-path access; it does not get
a Docker socket, host namespaces, Kubernetes API authority or an AWS identity.
Only that node-reader image carries the native journal tooling and Debian
package inventory; both role images receive independent scans and manifest pins.
An admission guard and negative server-side admission preflight are prerequisites
to starting that reader. Agent-to-gateway transport uses a dedicated mTLS trust
root and network policies. Job namespaces cannot ingest directly.

## Delivery

Collector output goes to a fixed private CloudWatch log group through a scoped
Pod Identity role. CloudWatch subscriptions feed a dedicated Firehose stream and
encrypted private versioned S3 archive. EKS control-plane audit/API/authentication,
Route 53 DNS, Network Firewall and VPC flow logs use AWS-native delivery into
the same archive instead of pretending an in-cluster agent can tail them.

The collector has no S3 permissions; the Firehose role has only the required
archive prefixes and encryption authority. A bounded Firehose processor retains
trusted AWS envelope identity and redacts supported secret patterns. Processor
failures have an explicitly sensitive restricted error prefix and alarms, not a
plaintext success fallback. Delivery diagnostics are excluded from their own
subscriptions to prevent recursive failure storms.

The source has disk-backed reader cursors and sending queues, bounded memory,
retry/backpressure, clean shutdown and loss monitoring. It does not promise
exactly-once delivery or unlimited outage retention. Disk exhaustion, permanent
authorization failures, retention expiry and undetectable application secrets
remain operational concerns with explicit tests/runbook actions.

## Supply and deployment

The Cornerstone repository is private. Public RunSecure source includes its
revision contract and build configuration, never a copied private source tree or
credential. Local collector builds consume a separately authorized pinned
checkout as a named build context. The qualified graph follows the current
0.164.0 collector release with contrib 0.164.1/core modules 1.70.0. Publishing
the resulting role artifacts and
provisioning cloud resources are separate approval steps.

The deployment chart stays disabled until qualified image digests, existing mTLS
Secrets, private endpoint peers, identity and storage inputs are supplied. Offline
render fixtures are deliberately non-operational. Live EKS acceptance still
requires the foundation's AZ-local DNS, exact Pod-policy and image-pull proofs.
No telemetry exception broadens application internet egress.

## Acceptance

- Canonical event/schema/registry tests cover success, failure, definition UUIDs,
  Kubernetes context, redaction and observable output errors.
- Workload event forgery, malformed JSON, nested secrets, oversized UTF-8 records
  and unsupported context cannot become trusted infrastructure events.
- A built collector must load the rendered production configuration and relay
  representative trusted, workload, host and AWS-native fixtures to an external
  archive test service, including authentication and restart/backpressure cases.
- Helm/admission/network-policy tests cover forbidden host mounts, identity,
  unsafe defaults, direct workload ingestion and immutable image selection.
- Mock-only Terraform tests cover archive IAM, KMS/S3 policies, subscriptions,
  retention and absence of application egress changes. They are not live proof.
- Independent whole-change review and normal repository checks precede handoff.
