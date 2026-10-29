# Cornerstone logging verification receipt

Local implementation checks completed 2026-10-29. No EKS, IAM, bucket, registry
publication, merge or release accompanied these checks. This receipt describes
source and an unpublished ARM64 test image, not a production delivery claim.

| Check | Result |
| --- | --- |
| Orchestrator and socket-proxy full Go suites with race detector | Pass; existing logic-coverage gate passes at 99% or above per package |
| Public collector adapter with race detector | Pass; adapter 99.5%, shared telemetry helper 100% |
| Canonical helper copies and deliberately introduced drift/missing-file checks | Pass |
| Bundled registry CLI and all 37 event definitions | Pass; canonical `cornerstone/v1` registry identifier |
| Helm/controller identity, strict schema and EKS source contracts | Pass |
| Collector chart plus actual built-distribution fixtures | 16 pass, including real schema/signature validation, explicit invalid definitions, mTLS rejection/acceptance, restart/queue recovery, diagnostic filtering and real Linux journal input |
| Admission CEL execution against malicious Pod variants | 18 rejection cases pass; no live Kubernetes admission receipt |
| Real compressed CloudWatch envelopes through the Python normalizer | 12 pass, including quoted/prefixed credentials, signed URLs and nested/scalar JSON syntax |
| Actual collector → local CloudWatch protocol receiver → actual transformer → external local object receiver/readback | Pass, including explicit failed-validation records; AWS API/IAM/KMS behavior is mocked |
| Terraform formatting, real provider-schema validation and mock-only plans | Pass; 16 plans, no apply |
| Existing repository pre-push hook | Pass without bypass |
| Independent bounded source reviews | Reported redaction, context-mapping, startup-guard and monitoring issues corrected; no structured Codex Security scan is represented as complete |

The distribution uses private Cornerstone source
`490fc072c02d72a0dc62633d0c4f573b6707b4ef`, public adapter source SHA256
`736b989ede0e723245bc63e08b31763f3a1fb68ee2de6aa587e2ce3c01e6584c`
and OCB/contrib 0.158.0/core 1.64.0. The runtime is digest-pinned Debian Trixie,
with real journalctl 257.13. Exact compatible security floors update the
assembled Go dependency graph; the coupled 0.20 OTEL log SDK/exporter API stays
on its supported line after an attempted 0.21 upgrade failed compilation.

The final Syft SBOM SHA256 is
`f8b43d738bc11a72f93e517c00617ae0612303982ab99086c7d5e47fa9c6f7c3`.
Grype 0.116.0 passes the existing `--fail-on high --only-fixed` policy with no
ignores. This is **not a clean unfiltered scan**: 174 package/advisory matches
remain: 0 Critical, 54 High, 53 Medium, 12 Low, 54 Negligible and 1 Unknown.
The 54 High package matches represent 14 distinct advisory IDs; 53 matches are
marked `wont-fix` and one `not-fixed`. Two Medium matches have available fixes
on the incompatible log SDK/exporter API line. Reachability and risk acceptance
for the remaining advisories are not established by this receipt. No suppression
was added and no vulnerable collector was activated in a cluster.

Before publication or commissioning, preserve/recreate the SBOM and complete
reports for the exact architecture-specific manifest, assess remaining findings,
and run the target-cluster acceptance checks in [the runbook](eks-logging.md).
Local Docker config IDs and transformed scanner manifest IDs must not be used
as production image pins. This source change does not modify the older EC2
runner's OSV findings or establish that its security coverage is clean.
