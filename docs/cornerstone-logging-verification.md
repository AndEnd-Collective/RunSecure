# Cornerstone logging verification receipt

Local qualification completed **2026-11-01 07:10 UTC**. No EKS, IAM, bucket,
registry publication, merge or release accompanied these checks. These are
source and unpublished Linux ARM64 candidate results; they do not establish
production delivery or Bottlerocket compatibility.

| Check | Result |
| --- | --- |
| Orchestrator/socket-proxy race and per-package logic coverage | Passed in the initial PR74 implementation; those components are unchanged by this collector update |
| Public collector adapter with race detector on the updated core graph | Pass; adapter 99.5%, single telemetry module 100% |
| One telemetry source: no module-local copies, consumer and OCB replaces, `telemetry` named context on every orchestrator/socket-proxy image build | Pass (`tests/validation/test-telemetry-single-source.sh`); orchestrator 99.6% and socket-proxy 99.4% coverage gates unchanged |
| Bundled registry CLI and all 37 event definitions | Pass; canonical `cornerstone/v1` registry identifier |
| Collector/chart/distribution fixtures against both rebuilt role images | **21 pass**, no skips; actual private schema/signature processors, invalid definitions, mTLS rejection/acceptance, restart/queue recovery, diagnostic filtering, Linux journal input including a compressed (>512 byte) entry, node journalctl-closure inventory and distro identity, minimal gateway filesystem and non-root startup/redaction/shutdown |
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
`d44a76d8bfc9d0f351523b47f45d8310b0c0e669a781a4455381bf5f4592a352`.
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
| Minimal gateway | `runsecure-collector-gateway:pr74-0164` | `sha256:46af4ab7899010974118cd143a616e426e98c9fdffa4693fa8aeabb1dec6c63e` | `11b0848daaf49e0c65208d5d20dca465113240ab158a508f8d4294cb2a77e572` |
| Journal-capable node reader | `runsecure-collector-node:pr74-0164` | `sha256:629da110583c88e194bb906d9780db7763e0277959b6206b5fdeda0f40bbf5bd` | `8b3914c10ade5f7bff3d51a6b5ca2c5791201f8905b36762cd4ff5e8bdbadab4` |

The gateway's saved image layers contain only the static collector and CA
bundle. Its fixture verifies Amazon Root CA 1 is present and the distrusted
emSign ECC G3 / Comodo AAA roots are absent. It starts as UID/GID 10001 with no
network, all capabilities dropped, no new privileges and read-only root,
emits one validated/redacted event, and exits cleanly on SIGTERM. The node is a
scratch image holding Debian Trixie's journalctl 257.13 and only its
shared-library closure (19 packages, plus the LZ4/XZ libraries systemd
dlopens), each with its dpkg status stanza and `os-release`, so scanners keep
both inventory and distro advisory matching. It ships no shell, package
manager, Perl, ncurses or util-linux tools. A
separate disposable producer supplies the read-only real journal fixture;
no shell or journal tooling is added to the gateway. Fixture containers and
owned journal volumes were removed after the suite.

## Scans and unresolved risk

Syft **1.55.0**, Grype **0.121.0**, database built
**2026-10-31T06:18:17Z**; both `--fail-on high --only-fixed` gates exit **0**.
No ignores or suppressions were added; the fixed-only reports contain zero
matches. Preserve the unfiltered reports alongside them:

| Role | Critical | High | Medium | Low | Negligible | Unknown | Total matches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Gateway | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| Node reader | 0 | 18 | 20 | 6 | 22 | 1 | 67 |

The previous full-Debian node carried 56 High matches on this database. The
journalctl closure leaves **18 High matches across 10 distinct advisory IDs**,
all in libraries journalctl loads: glibc (CVE-2026-19499, CVE-2026-5435,
CVE-2026-84243), util-linux's libblkid/libmount (CVE-2026-76642, -78408,
-78409, -78410, each also attributed to the `util-linux` source package), ACL
(CVE-2026-54369, -54370) and zlib (CVE-2026-85091). The database marks 16
matches `wont-fix` and two `not-fixed`; this describes scanner fix availability,
not exploitability or risk acceptance. Removing them requires dropping
journalctl itself, which the journald receiver invokes. No reachability
assessment establishes that these findings are harmless.

Both images retain module-level **GO-2026-5932** (`golang.org/x/crypto` 0.58.0,
Unknown, no fixed version), which concerns the unmaintained OpenPGP packages
([official advisory](https://pkg.go.dev/vuln/GO-2026-5932)). The actual assembled
`GOOS=linux GOARCH=arm64 go list -deps .` graph contains no
`golang.org/x/crypto/openpgp` package or descendants. Its saved package-list
SHA256 is `03bdb5134fea3246a2a991bb6d19296e89b536fde6d8051ce17b62765ff49665`.
This is bounded compiled-package evidence for this candidate; the unfiltered
match remains visible, and Grype's stripped-binary module matching does not
independently establish function reachability. Do not label either report
unconditionally clean.

The unfiltered report SHA256s are
`7c51901a003fb7fad08ecf2fdc5dbb997295e863557273e585cd7f56dae8da36`
(gateway) and
`6fe18a4c985c29e3441aceea121888edb518cdfdee0ccd41678431b8b500bf8c`
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

PR74's self-CI ran on the one-shot `bootstrap-self-runner.sh` runner (one
job, then exit; no daemon): `lints-on-self` passed on
`c445ad9` in [dogfood run 41283996600](https://github.com/AndEnd-Collective/RunSecure/actions/runs/41283996600),
after the superseded runs were cancelled. Hosted validation, smoke/integration,
Kubernetes integration and runner-image scans also passed on that head. This
does not resolve the older EC2 runner's OSV uncertainty or establish clean
security coverage there.
