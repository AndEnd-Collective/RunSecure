# Cornerstone logging verification receipt

Local qualification completed **2026-10-29 08:25 UTC**. No EKS, IAM, bucket,
registry publication, merge or release accompanied these checks. These are
source and unpublished Linux ARM64 candidate results; they do not establish
production delivery or Bottlerocket compatibility.

| Check | Result |
| --- | --- |
| Orchestrator/socket-proxy race and per-package logic coverage | Passed in the initial PR74 implementation; those components are unchanged by this collector update |
| Public collector adapter with race detector on the updated core graph | Pass; adapter 99.5%, mirrored telemetry helper 100% |
| Canonical helper copies and deliberately introduced drift/missing-file checks | Pass |
| Bundled registry CLI and all 37 event definitions | Pass; canonical `cornerstone/v1` registry identifier |
| Collector/chart/distribution fixtures against both rebuilt role images | **20 pass**; actual private schema/signature processors, invalid definitions, mTLS rejection/acceptance, restart/queue recovery, diagnostic filtering, Linux journal input, minimal gateway filesystem and non-root startup/redaction/shutdown |
| Admission CEL execution against malicious Pod variants | **20 cases**: exact reader allowed and **19** hostile variants rejected, including the gateway image; no live Kubernetes admission receipt |
| Real compressed CloudWatch envelopes through the Python normalizer | 12 pass, including quoted/prefixed credentials, signed URLs and nested/scalar JSON syntax |
| Actual collector → local CloudWatch protocol receiver → actual transformer → external local object receiver/readback | Pass, including explicit failed-validation records; AWS API/IAM/KMS behavior is mocked |
| Terraform formatting, real provider-schema validation and mock-only plans | Pass; 16 plans, no apply |
| Existing repository pre-push hook | Pass without bypass |
| Independent bounded source review of the collector update | No Critical/Important production-source issue reported; a compatible x/net security floor was restored after review identified dependency matches |

## Exact local candidate and supported graph

The distribution consumes the unchanged private Cornerstone source
`490fc072c02d72a0dc62633d0c4f573b6707b4ef` and public adapter
`normalize.go` SHA256
`736b989ede0e723245bc63e08b31763f3a1fb68ee2de6aa587e2ce3c01e6584c`.
The strict OCB build and actual runtime fixtures qualify these processors on
Collector release **0.164.0**, stable core modules **1.70.0**, and contrib
**0.164.1**. The resolved log SDK and OTLP gRPC log exporter are both **0.21.0**;
the two Medium SDK/exporter findings recorded for the earlier 0.158 candidate
are absent from both new reports. Only x/net is explicitly raised to **0.62.0**
for GO-2026-6860/6866; no older SDK/API overrides remain.

The release selection follows the
[official 0.164.0 manifest](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-releases/v0.164.0/distributions/otelcol-contrib/manifest.yaml)
and the project's [latest-minor support policy](https://github.com/open-telemetry/opentelemetry-collector/security/policy),
checked 2026-10-29. These versions remain an exact tested snapshot, not a promise
that a future release is automatically qualified.

| Role | Unpublished local tag | BuildKit ARM64 image manifest | Syft SBOM SHA256 |
| --- | --- | --- | --- |
| Minimal gateway | `runsecure-collector-gateway:pr74-0164` | `sha256:1acc463cd7536b4b542bd16ed777a8a63f52ea6226e00738eeb19a9b9a98989b` | `3927eee03ec29c013c1181aa954a06b4812b6de96c5872068ace63bf153ed167` |
| Journal-capable node reader | `runsecure-collector-node:pr74-0164` | `sha256:a16e2bbf757b2327fbd0a7722f0ea85c3a05e01c136e685db6d7e1cacdd64fb0` | `937ce16b76c1d32d1ef06051d76101bcd572ef80aa9588e07c55ed6c6cef257a` |

The gateway's saved image layers contain only the static collector and CA
bundle. Its fixture verifies Amazon Root CA 1 is present and the distrusted
emSign ECC G3 / Comodo AAA roots are absent. It starts as UID/GID 10001 with no
network, all capabilities dropped, no new privileges and read-only root,
emits one validated/redacted event, and exits cleanly on SIGTERM. The node keeps
Debian Trixie's packaged journalctl 257.13, native closure and inventory. A
separate disposable producer supplies the read-only real journal fixture;
no shell or journal tooling is added to the gateway. Fixture containers and
owned journal volumes were removed after the suite.

## Scans and unresolved risk

Syft **1.48.0**, Grype **0.116.0**, database built
**2026-10-29T06:23:34Z**; both `--fail-on high --only-fixed` gates exit **0**.
No ignores or suppressions were added; the fixed-only reports contain zero
matches. Preserve the unfiltered reports alongside them:

| Role | Critical | High | Medium | Low | Negligible | Unknown | Total matches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Gateway | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| Node reader | 0 | 54 | 51 | 12 | 54 | 1 | 172 |

The 54 High node package matches remain **14 distinct advisory IDs** across
Perl, zlib, ncurses, GCC, glibc, util-linux and ACL. The database marks 53
matches `wont-fix` and one `not-fixed`; this describes scanner fix availability,
not exploitability or risk acceptance. They are inherited native-runtime
findings, retained with their package inventory. The minimal gateway does not
remediate the node's native vulnerabilities, and no reachability assessment
establishes that these findings are harmless.

Both images retain module-level **GO-2026-5932** (`golang.org/x/crypto` 0.58.0,
Unknown, no fixed version), which concerns the unmaintained OpenPGP packages
([official advisory](https://pkg.go.dev/vuln/GO-2026-5932)). The actual assembled
`GOOS=linux GOARCH=arm64 go list -deps .` graph contains no
`golang.org/x/crypto/openpgp` package or descendants. Its saved package-list
SHA256 is `db2a74c28c334f392a09ad0fbf4b940b3a40e7a0f73cac432e1717b5ebd62bcc`.
This is bounded compiled-package evidence for this candidate; the unfiltered
match remains visible, and Grype's stripped-binary module matching does not
independently establish function reachability. Do not label either report
unconditionally clean.

The unfiltered report SHA256s are
`3cb3180cdd43a0b1fec996befab96c6b28e9a68960722acd17469eda55a36bcb`
(gateway) and
`99ae50e23d760491850b1b1da4b7e6f7dbb9fee26d6e91ce8e40a72374fc4175`
(node). Builds, SBOMs and full reports are held outside the public source tree.

## Remaining commissioning boundaries

Before publication, preserve/recreate the SBOM and complete reports for the
exact architecture-specific registry manifest, assess remaining findings and
obtain the required artifact/deployment approvals. BuildKit manifests above
identify only unpublished local candidates. Verify registry readback before
using production image pins; local Docker IDs are not that evidence.

Run the target-cluster acceptance checks in [the runbook](eks-logging.md):
Bottlerocket journal format/path/rotation/reboot coverage, fail-closed admission,
CNI isolation, private image pulls, Pod Identity, CSI encryption, mTLS rotation,
queue/disk/loss alerts and real AWS/S3 archive readback. None was live-tested by
this receipt. No completed structured Codex Security scan is claimed.

PR74's one-shot credentialed self-CI startup and cancellation of its superseded
queued run remain pending owner approval after automatic approval review
rejected those exact actions; neither was retried for this qualification.
Hosted checks and local results must not be presented as completion of that
pending self-CI job. This change also does not resolve the older EC2 runner's
OSV uncertainty or establish clean security coverage there.
