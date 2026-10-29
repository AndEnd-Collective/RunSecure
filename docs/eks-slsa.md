# SLSA controls and evidence for the EKS example

Last checked: **2026-10-29 03:46:13 UTC**. This document maps controls to evidence;
it does not assess or certify a deployed platform. No illustrative Terraform,
Helm configuration, image scan, or successful CI run alone establishes a SLSA level.

The current approved specification is **SLSA v1.2**, with separate Build and Source
tracks. Build L1 requires provenance, L2 adds authentic provenance from a hosted
platform, and L3 adds hardened provenance generation and isolation. Source L1 is
version control; L2 adds retained history and source provenance; L3 adds continuous
technical controls; L4 adds two-party review. Specify the version and track in any
future assessed claim. [SLSA tracks](https://slsa.dev/spec/v1.2/tracks),
[Build levels](https://slsa.dev/spec/v1.2/build-track-basics),
[Source requirements](https://slsa.dev/spec/v1.2/source-requirements)

## Controls and required evidence

| Area | Intended control | Evidence and unresolved obligations |
| --- | --- | --- |
| Builder identity | Use a reviewed reusable release workflow pinned by full commit SHA; restrict its callers, inputs and release triggers. | Define the complete trusted platform: GitHub, workflow owners, RunSecure controller, cluster/node administrators, admission controls, node software and image supply chain. Preserve workflow identity, revision, source revision and invocation evidence. A runtime image digest is not itself a builder identity. |
| Provenance and signing | Build and attest within the trusted reusable workflow; bind the statement to the exact output digest. | Demonstrate that untrusted build steps cannot forge required provenance or access signing credentials. A later signing step in a compromised job does not establish that separation. Retain the attestation bundle and its verification policy. |
| Source controls | Protect release branches/tags and workflow changes; require final-revision review and checks; restrict bypass rights. | Retain continuous enforcement and review evidence. Source provenance/VSA is separate from build provenance. Branch protection settings alone do not establish Source L2–L4. |
| Job isolation | Use one-job JIT registration, fresh Pods/workspaces, restricted containers and separate trust pools. | Test simultaneous jobs, subsequent jobs, cleanup, secret isolation and cache poisoning. Namespace separation does not prove isolation from the shared node kernel or administrators. Establish node recycling and cache trust rules. |
| Inputs and egress | Pin images, Actions and workflows immutably; use lockfiles/checksums and approved proxy destinations. | Record external parameters and dependencies. Network allowlists do not prove reproducibility or hermeticity. Confirm the actual CNI/firewall path, including failures and startup transitions. |
| Consumer enforcement | Verify exact artifact digest, expected repository, signer workflow/revision and source revision before use. | Reject missing provenance, changed artifacts, unexpected signers and unexpected source. If admission is used, test its namespace selection and failure policy as well as its installed resources. |
| Operations | Preserve diagnostics, audit records, policy changes and acceptance receipts; update platform dependencies. | Define retention/access controls, incident response, trusted-image approval and recurring isolation tests. Vulnerability scanning is a separate control, not a SLSA-level measurement. |

Build L3 requires trusted control-plane generation/verification, protected signing
material, ephemeral environments, resistance to cross-build influence and cache
poisoning. It does not mandate network-free builds or a particular VM/container
technology. This example still needs a platform assessment and execution evidence.
[Build requirements](https://slsa.dev/spec/v1.2/build-requirements)

Source L4 permits a trusted uploader and a different trusted reviewer, or two
trusted reviewers. Approval must cover the final revision and its target context.
Do not substitute a build attestation for the source-system evidence needed by the
Source track. [Source requirements](https://slsa.dev/spec/v1.2/source-requirements)

## GitHub attestations and self-hosted runners

GitHub's documented artifact-attestation and reusable-workflow guidance explicitly
discusses **SLSA v1.0** Build L2/L3. It is useful implementation guidance, not an
automatic v1.2 assessment of this EKS topology. Its reusable workflow performs both
the build and attestation; both caller and called workflow need `contents: read`,
`id-token: write` and `attestations: write`. Scope these capabilities to the protected
release path. Registry publishing permissions are separate; ECR does not require
granting GitHub Packages write access merely to publish to ECR.
[Reusable workflow guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating)

Private/internal repositories require GitHub Enterprise Cloud for this feature;
Free, Pro and Team support public repositories. Check eligibility before choosing
this mechanism. [Availability](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)

Public-repository attestations use the public Sigstore transparency log. Private
repositories use GitHub's Sigstore instance without that log. Preserve the expected
trust root, signed timestamps and bundles appropriate to the chosen service.
Attestations establish origin claims, not that code is safe; they must be verified
to provide a consumption control.
[Attestation semantics](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

JIT registration limits a runner to at most one job. Reusing its underlying hardware
still requires a clean environment. Separate untrusted PR jobs from release/signing
trust pools, restrict repository access, and prove that job Pods cannot reach node
metadata, controller credentials or other sensitive services. Kubernetes token
automount being disabled does not establish AWS credential isolation.
[Self-hosted runner security](https://docs.github.com/en/actions/reference/security/secure-use)

## Consumer verification example

The following is a policy template, **not an actual approved builder identity**.
An operator must supply every expected value from a separately reviewed release
policy, not from the artifact or its unverified attestation. Use a tested, pinned
GitHub CLI version supporting these flags, and authenticate to the exact OCI
registry separately with read-only access.

```bash
#!/usr/bin/env bash
set -euo pipefail
: "${EXPECTED_IMAGE:?Set registry/repository@sha256:manifest-digest}"
: "${EXPECTED_SOURCE_REPOSITORY:?Set owner/repository}"
: "${EXPECTED_SOURCE_COMMIT:?Set the approved full source commit SHA}"
: "${EXPECTED_SOURCE_REF:?Set the approved refs/heads/... or refs/tags/...}"
: "${EXPECTED_SIGNER_WORKFLOW:?Set owner/repository/.github/workflows/release.yml}"
: "${EXPECTED_SIGNER_COMMIT:?Set the approved full reusable-workflow commit SHA}"

[[ "$EXPECTED_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || exit 1
[[ "$EXPECTED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ "$EXPECTED_SIGNER_COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 1

gh attestation verify "oci://$EXPECTED_IMAGE" \
  --repo "$EXPECTED_SOURCE_REPOSITORY" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-workflow "$EXPECTED_SIGNER_WORKFLOW" \
  --signer-digest "$EXPECTED_SIGNER_COMMIT" \
  --source-digest "$EXPECTED_SOURCE_COMMIT" \
  --source-ref "$EXPECTED_SOURCE_REF" \
  --predicate-type https://slsa.dev/provenance/v1
# Consume the exact digest only after this command succeeds.
```

The reusable workflow is the signer. Repository/owner matching alone is broader
than this policy. The CLI defaults to retrieving attestations through GitHub;
offline/OCI bundles have different repository-name continuity considerations.
Certificate identity and verified timestamps have stronger origin guarantees than
potentially workflow-controlled predicate fields. Add reviewed predicate policy
for build-specific expectations, with negative tests; do not trust arbitrary JSON
fields just because a signature verified.
[CLI verification reference](https://cli.github.com/manual/gh_attestation_verify)

## EKS acceptance gates still outstanding

Keep `scope.repos` empty until exact-topology acceptance succeeds. RunSecure stamps
a per-job **Secret owner reference** on its directly created runner/proxy Pods;
this is not a Deployment/Job-owned Pod. AWS documents reliability limitations for
standalone Pods. Confirm NetworkPolicy enforcement for these exact Secret-owned
Pods, including denied direct internet, metadata and cross-project traffic and
allowed runner-to-proxy traffic. A policy object existing is not enforcement proof.
[AWS CNI constraints](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html)

Further required evidence includes actual controller API/DNS peers, node PID limits,
job/cloud identity isolation, release-builder separation, secret provisioning,
diagnostic retention and recovery. The shipped controller policy permits public
IPv4 HTTP(S); `orchEgress.allowDomains` alone does not enforce destination domains.
External firewall claims require independent acceptance. Attestation admission,
if selected, also needs an effective policy and explicitly selected namespaces;
installing a controller alone does not enforce it.
[GitHub admission guidance](https://docs.github.com/actions/security-guides/enforcing-artifact-attestations-with-a-kubernetes-admission-controller)
