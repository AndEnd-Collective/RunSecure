# Illustrative private EKS / Bottlerocket foundation

Read [the guidebook](../../docs/eks-guidebook.md) before using these files.
Nothing here was applied. The example intentionally leaves execution internet
domains and Helm repository enrollment empty; it is not a commissioned runner.
The empty Helm values are render-only: the controller rejects an empty scope.
Complete platform-fixture acceptance, then approve one enrollment before install.

The root uses native AWS provider **6.71.0** for exact SNI plus Route 53-resolved
IP validation, symmetric same-AZ inspection and separate private platform paths.
Do not downgrade to SNI-only filtering. Supply reviewed roles, repository ARNs,
exact compatible versions and endpoint/DNS details; placeholders fail validation
or cannot run. Existing IAM role contents, AZ-local DNS and policy enforcement
on RunSecure's Secret-owned Pods require independent target-cluster proof.

Local checks do not need AWS credentials:

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test -test-directory=tests
helm lint ../../charts/runsecure-orchestrator -f helm-values.example.yaml
helm template runsecure ../../charts/runsecure-orchestrator \
  -f helm-values.example.yaml > /tmp/runsecure-eks-rendered.yaml
```

The Terraform tests use mock providers and plan-only runs. They do not validate
AWS API acceptance or create resources. `terraform.tfvars.example` is a field
inventory, not a deployable account configuration. Terraform does not install
the chart, create App credentials or start jobs. Use normal reviewed planning
and deployment procedures only after filling the guidebook's prerequisites.
