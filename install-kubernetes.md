# Installing the RunSecure Orchestrator (Kubernetes backend)

This guide walks through deploying the RunSecure orchestrator to an existing
Kubernetes cluster using the Helm chart at `charts/runsecure-orchestrator/`.
One Helm release runs one controller for one scope. Shared mode maps each
approved repository to its own execution namespace and uses operator-approved
inline runner configuration. Legacy mode keeps runners in the scope namespace
and fetches `runner.yml` from GitHub. Both modes use per-job runner+proxy Pods,
namespace-scoped NetworkPolicies and RBAC.

For the Compose backend (Linux/macOS host with Docker), see
[`install.md`](install.md).

For an illustrative private EKS foundation with Bottlerocket workers, exact
GitHub network controls, staged DNS/bootstrap and operational acceptance gates,
see the [EKS guidebook](docs/eks-guidebook.md) and
[Terraform/Helm examples](examples/eks-bottlerocket/). Target-cluster acceptance
is required; the existing kind/Calico tests are not EKS commissioning evidence.

---

## 1. Prerequisites

### Cluster

- **Kubernetes ≥ 1.26** (chart `kubeVersion` gate).
- **A NetworkPolicy-enforcing CNI — required for the runner egress-isolation
  claims to hold.** Calico and Cilium enforce NetworkPolicy. kindnet and
  flannel do NOT. If your cluster's CNI does not enforce NetworkPolicy,
  the per-spawn `RunnerEgressNetworkPolicy` and `ProxyIngressNetworkPolicy`
  objects are created but silently ignored — the runner Pod can reach the
  internet directly, bypassing the proxy. Verify enforcement before relying
  on the network isolation claims in `SECURITY.md`.
- **Pod Security Standards (PSS) Restricted admission** on the
  `runsecure-<scope>` namespace. The chart applies the required labels; the
  cluster must have PSS admission enabled (standard since k8s 1.25).
- **A bounded kubelet `podPidsLimit` on every eligible runner node.** The core
  Kubernetes Pod API has no per-Pod PID-limit field, so the `pids` value in
  `runner.yml` is enforced by the Compose backend only. The Kubernetes backend
  enforces that file's CPU and memory values per Pod, but relies on this
  node-level kubelet setting for process-count containment.
- **Helm ≥ 3.12**.

### Optional

- **cert-manager** — required only to emit the optional compatibility certificate
  resources when `tls.enabled: true`. Kubernetes has no Docker socket-proxy hop;
  these resources do not establish an additional runtime mTLS channel.

### Local tools

- `kubectl` authenticated against the cluster.
- `helm` 3.12+.

---

## 2. Choose authentication: PAT or GitHub App

The orchestrator needs a GitHub credential scoped to the repos in the scope.

### Option A: Fine-grained Personal Access Token (PAT)

Create at <https://github.com/settings/tokens?type=beta>:

| Permission | Why |
|---|---|
| **Administration: Read & Write** | `POST /repos/{repo}/actions/runners/generate-jitconfig` (every spawn) and `DELETE /repos/{repo}/actions/runners/{id}` (leak cleanup). |
| **Actions: Read** | `GET /repos/{repo}/actions/runs?status=queued` (poll endpoint). |
| **Metadata: Read** | Auto-included; not optional. |

Set repository access to *Only select repositories* — exactly the repos the
scope will serve. Expiration ≤ 90 days.

Create a Kubernetes Secret with the token:

```sh
kubectl create namespace runsecure-<scope>
kubectl create secret generic runsecure-pat \
  --from-literal=pat=github_pat_XXXX... \
  -n runsecure-<scope>
```

In your values file (see step 4), set:

```yaml
auth:
  type: pat
  pat:
    existingSecretName: runsecure-pat
```

### Option B: GitHub App (least-privilege installation tokens)

GitHub App tokens are installation-scoped, auto-rotating, and do not carry
a user identity. Prefer this in shared/team environments.

1. Create a GitHub App at <https://github.com/settings/apps/new>:
   - **Permissions:** `Administration: Read & Write` (runners), `Actions: Read`.
   - **Where to install:** select the repositories the scope will serve.
   - Generate a private key (PEM). Note the App ID and Installation ID.

2. Create a Kubernetes Secret with the private key:

   ```sh
   kubectl create secret generic runsecure-app-key \
     --from-file=private-key=/path/to/private-key.pem \
     -n runsecure-<scope>
   ```

3. In your values file, set:

   ```yaml
   auth:
     type: github_app
     app:
       appId: "12345"
       installationId: "67890"
       privateKeySecretName: runsecure-app-key
   ```

The Kubernetes controller requires mode 0440 and reads the projected Secret
through its non-root fsGroup. Compose retains mode 0400.

---

## 3. Enable self-hosted runners in each target repo

This is required regardless of auth method:

1. Open the repo's *Settings → Actions → Runners*.
2. Toggle *Allow self-hosted runners*.

If this toggle is off, the `generate-jitconfig` API returns 422; the
orchestrator's circuit breaker opens after 5 consecutive failures and stops
polling that repo until the toggle is enabled.

---

## 4. Create a values file

Create `my-scope-values.yaml` (do not commit auth secrets inline; use
`existingSecretName` / `privateKeySecretName` as shown above):

```yaml
kubernetesNetwork:
  # Configure exact API CIDR/port pairs for both Service and endpoint traffic.
  # Separate pairs prevent the Service address from inheriting an endpoint port.
  apiServerPeers:
    - cidr: "10.96.0.1/32"
      port: 443
    - cidr: "172.18.0.2/32"
      port: 6443
  # DNS policy may see the Service /32 before DNAT or the selected Pod after
  # DNAT, depending on the CNI, so both exact forms are required.
  dnsServiceCIDRs:
    - "10.96.0.10/32"
  dnsNamespace: "kube-system"
  dnsPodLabel:
    key: "k8s-app"
    value: "kube-dns"

scope:
  name: "production"          # Becomes the namespace: runsecure-production
  backend: kube               # Must be 'kube' for this chart.
  globalMaxRunners: 10
  pollIntervalSeconds: 15
  securityProfile: strict
  allowProjectOverrides:
    - allow_wildcards
  orchEgress:
    allowDomains:
      - api.github.com
  repos:
    - repo: owner/repo-a
      maxConcurrent: 3
    - repo: owner/repo-b
      maxConcurrent: 2

auth:
  type: pat
  pat:
    existingSecretName: runsecure-pat

image:
  orchestrator:
    repository: ghcr.io/andend-collective/runsecure/orchestrator
    tag: "2.2.0"
    # Replace with the real digest from the approved 2.2+ release — see step 6.
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  proxy:
    repository: ghcr.io/andend-collective/runsecure/proxy
    tag: "2.2.0"
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  socketProxy:
    repository: ghcr.io/andend-collective/runsecure/socket-proxy
    tag: "2.2.0"
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

### Shared controller with separate project namespaces

Shared mode requires an explicitly pinned RunSecure 2.2+ controller. The chart
retains 2.1.10 image defaults for legacy installs and rejects that bundled
controller digest when project namespaces are configured. Load the exact
controller, proxy and terminal runner digests from the approved 2.2+ release
manifest into the existing `image.*` values before installing; setting a newer
`tag` alone does not replace a digest. No release digests are invented here.

Replace `scope.repos` in the example with explicit enrollment:

```yaml
scope:
  repos:
    - repo: owner/repo-a
      namespace: ci-project-a
      maxConcurrent: 3
      runnerConfig:
        runtime: node:24
        labels: [self-hosted, Linux, ARM64, container]
        resources: {memory: 2g, cpus: 2, pids: 256}
        httpEgress: [registry.npmjs.org]
        orchestrator: {timeoutSeconds: 21600}
      kubernetes:
        nodeSelector: {dedicated: ci}
        tolerations:
          - {key: dedicated, operator: Equal, value: ci, effect: NoSchedule}
        ephemeralStorage: 10Gi
        proxyResources: {cpu: 250m, memory: 256Mi, ephemeralStorage: 1Gi}
    - repo: owner/repo-b
      namespace: ci-project-b
      maxConcurrent: 2
      runnerConfig:
        runtime: python:3.12
        labels: [self-hosted, Linux, ARM64, container]
        resources: {memory: 2g, cpus: 2, pids: 256}
        httpEgress: [pypi.org, files.pythonhosted.org]
```

The management namespace `runsecure-production` contains the only controller,
its ServiceAccount, GitHub App key/PAT and mounted scope configuration. Each
project namespace contains only that project's transient runner/proxy stacks.
Helm precreates all namespaces, labels them PSS Restricted, installs default
deny policies and binds the management ServiceAccount with a separate Role in
each enrolled execution namespace. Runtime permissions cannot create namespaces
or act in an unenrolled namespace. Shared mode grants no workload Role in the
management namespace. The controller is a trusted boundary: its credential and
all enrolled namespace permissions cover every project in its scope.

Once a namespace or shared-only setting is declared, every repository must have
a distinct namespace and approved `runnerConfig`. Reserved/controller namespaces, duplicate identities,
missing policies and malformed runtime, label, image and resource values fail
closed. A workflow cannot choose its namespace or submit a Pod manifest. Shared
mode does not call the Contents API for policy, including on the default branch.
Change approved configuration through the values file with a normal Helm upgrade;
the scope checksum restarts the controller to load the new fixed configuration.

`runnerConfig` and nested chart values use camelCase. The rendered `scope.yml`
uses canonical snake_case (`runner_config`, `http_egress`, `node_selector`, etc.).
An optional project `runnerImage: registry.example/terminal@sha256:<64 hex>`
overrides runtime image selection and must satisfy the terminal image contract.
Otherwise the selected runtime resolves an operator-pinned image environment
variable. Mutable image tags are rejected.

Both runner and proxy receive the project's selectors and tolerations. `ARM64`
labels select `kubernetes.io/arch=arm64`; `X64` selects `amd64`; without an
architecture label the default is `amd64`. Conflicting architecture or non-Linux
selectors fail. No automatic architecture translation is performed. Requests
equal limits for runner CPU/memory/disk and proxy CPU/memory/disk. Omitted disk
and proxy bounds default to 10Gi runner storage and 250m/256Mi/1Gi proxy resources.
Kubelet storage accounting and node-level PID limits remain cluster prerequisites;
namespace isolation is not a separate kernel or a VM boundary.

At idle there are zero runner/proxy Pods in the project namespaces; the one
controller keeps polling. A queued compatible job is observed on a poll, waits
for existing capacity if needed, and creates one pair of Pods. Cold-start latency
includes up to a poll interval, GitHub JIT registration, scheduling, image pulls
and any external node provisioning. RunSecure does not scale cluster nodes.
Configure node autoscaling externally; a pending Pod is not proof of node
capacity. `globalMaxRunners` and each `maxConcurrent` bound admission, while
in-memory reservations prevent repeated polls from duplicating pending work.
The existing targeting labels must match and every requested job label must be
present on the actual runner, including generated `runsecure-jit` and
`runsecure-scope-<scope>` ownership labels where requested.

On controller restart, recovery searches only enrolled namespaces and validates
scope/repository/namespace ownership before cleanup, deregistering exact GitHub
runners before deleting owning Secrets. There is one active replica with
`Recreate`; no leader election or HA is provided. Removing or renaming an enrolled
namespace requires draining its work first and retaining access until cleanup is
confirmed. GitHub registration cleanup and Kubernetes object cleanup are both
required before capacity is considered recovered.

### Values reference

| Key | Default | Description |
|---|---|---|
| `kubernetesNetwork.apiServerPeers` | `[{cidr: "10.96.0.1/32", port: 443}]` | Unique exact CIDR/port pairs for the Kubernetes Service and API endpoints. |
| `kubernetesNetwork.dnsServiceCIDRs` | `["10.96.0.10/32"]` | Unique exact `/32s` for cluster DNS Services visible before DNAT. |
| `kubernetesNetwork.dnsNamespace` | `"kube-system"` | Exact namespace containing the cluster DNS Pods. |
| `kubernetesNetwork.dnsPodLabel` | `{key: k8s-app, value: kube-dns}` | Exact identifying label shared by the cluster DNS Pods. |
| `replicaCount` | `1` | Fixed at one because the orchestrator has no distributed leader election. |
| `terminationGracePeriodSeconds` | `90` | Minimum drain window; lower values are rejected. |
| `scope.name` | `"default"` | Short lowercase name; becomes the k8s namespace `runsecure-<name>`. |
| `scope.backend` | `kube` | Must be `kube` for this chart. |
| `scope.globalMaxRunners` | `5` | Ceiling on concurrent runner Pods across all repos in the scope. |
| `scope.pollIntervalSeconds` | `15` | How often the orchestrator polls GitHub for queued jobs. Minimum 5. |
| `scope.securityProfile` | `strict` | `strict` \| `standard` \| `permissive`. Controls per-project override permissions. |
| `scope.repos` | `[]` | Legacy `{repo, maxConcurrent}` or shared `{repo, namespace, maxConcurrent, runnerConfig, runnerImage?, kubernetes?}` entries. |
| `auth.type` | `pat` | `pat` or `github_app`. |
| `auth.pat.existingSecretName` | `""` | Name of a pre-existing Secret with key `pat`. |
| `auth.app.appId` | `""` | GitHub App ID (string). |
| `auth.app.installationId` | `""` | GitHub App installation ID (string). |
| `auth.app.privateKeySecretName` | `""` | Name of a pre-existing Secret with key `private-key` (PEM). |
| `tls.enabled` | `false` | Emit optional compatibility cert-manager resources; Kubernetes has no socket-proxy hop or added runtime mTLS channel. |
| `tls.selfSigned` | `true` | Emit a cert-manager self-signed Issuer. Set `false` to reference an existing Issuer. |
| `tls.issuerName` | `""` | Name of an existing Issuer/ClusterIssuer when `tls.selfSigned=false`. |
| `image.*.digest` | placeholder | Pin by digest — see step 6. Digest takes precedence over tag. |

---

## 5. Install the chart

```sh
helm install runsecure-production charts/runsecure-orchestrator/ \
  -f my-scope-values.yaml \
  -n runsecure-production \
  --create-namespace
```

The chart creates:

- **Namespace** `runsecure-<scope>` with PSS Restricted labels.
- **ServiceAccount** for the orchestrator (namespace-scoped; no ClusterRole).
- **Role + RoleBinding** — least-privilege: `pods`, `services`, `secrets`,
  `networkpolicies` verbs `create/get/list/watch/delete` in each enrolled
  execution namespace (legacy mode: scope namespace only).
- **Default-deny NetworkPolicy** — denies all ingress and egress to every
  Pod in the namespace; two allow policies carve out only what the
  orchestrator needs (kube-apiserver, kube-dns, external HTTPS for GitHub).
- **ConfigMap** with the rendered scope config.
- **Orchestrator Deployment** (single replica, `Recreate` strategy, at least
  90 seconds termination grace; distroless, non-root UID 1001, `cap_drop: ALL`,
  read-only root filesystem, `seccompProfile: RuntimeDefault`). Multiple
  replicas are rejected because RunSecure does not use distributed leader election.
- **Service** exposing `/healthz` and `/readyz` on port 8080 plus `/metrics`
  and `/state/snapshot` on port 8081 (ClusterIP only; not externally
  accessible).
- (Conditional) **Certificate + Issuer** when `tls.enabled: true`.

The management listeners bind before cold-start runner reconciliation begins.
During that phase `/healthz` reports process liveness, while `/readyz` remains
`503` until the backend is initialized and every configured repository has a
fresh successful demand poll. After polling begins, `/healthz` also fails when
the poll loop becomes stale. This keeps slow, legitimate cleanup alive without
advertising the orchestrator as ready to receive work.

### Per-spawn objects (created at runtime, not by Helm)

For each CI job the orchestrator spawns:

- **Secret** — carries the GitHub JIT runner config and rendered Squid/HAProxy
  egress configs. Acts as the owning object; deleting it cascades GC to all
  other spawn resources.
- **ClusterIP Service** — proxy's stable DNS name inside the namespace.
- **NetworkPolicies** (3 per spawn):
  - `RunnerEgressNetworkPolicy` — runner → exact cluster DNS Service `/32s`
    plus exact selected DNS Pods on port 53, and its own proxy on port 3128;
    all other egress blocked.
  - `ProxyEgressNetworkPolicy` — proxy → the same dual exact pre/post-DNAT
    DNS peers (53/UDP+TCP) + internet (via Squid allow-list at L7).
  - `ProxyIngressNetworkPolicy` — only this spawn's runner Pod may connect to
    this spawn's proxy. Cross-spawn connections are blocked by pinning both the
    target (`runsecure.io/role=proxy`) and source (`runsecure.io/role=runner`)
    selectors to the same `runsecure.io/spawn-id`. This policy is load-bearing:
    without it, the namespace default-deny blocks runner→proxy connections even
    when the runner has a matching egress rule.
- **Proxy Pod** — runs Squid + HAProxy + optional dnsmasq. Receives egress
  configs from the Secret mount.
- **Runner Pod** — the hardened GitHub Actions runner. `HTTP_PROXY` is set to
  the proxy Service DNS name; apart from exact cluster DNS Service `/32s` and
  selected DNS Pods, the runner has no path other than its own proxy. CPU and
  memory requests equal the approved configuration limits; ephemeral storage
  is bounded and the memory-backed `/tmp` volume is capped at 512 MiB.

All per-spawn Pods run under PSS Restricted with `runAsUser: 1001`,
`cap_drop: ALL`, `seccompProfile: RuntimeDefault`, no host namespaces, and
`automountServiceAccountToken: false`. `readOnlyRootFilesystem: true` holds
for every container **except the runner container**, whose rootfs is
writable-by-necessity: the GitHub Actions runner writes `run-helper.sh` into
its own install dir at job start, so a read-only rootfs breaks every job.
This is the single relaxed axis on the runner (the proxy Pod stays fully
read-only) and mirrors the Compose backend — see SECURITY.md.

### Runner images and bringing your own

The runner image per `runtime:` is resolved from `RUNSECURE_RUNNER_IMAGE_<RUNTIME>`
(falling back to `RUNSECURE_RUNNER_IMAGE_DEFAULT`), set via the chart's
orchestrator env. Custom images work with no code changes and follow the same
contract as the Compose backend (ship the actions-runner at
`/home/runner/actions-runner` and the launcher at `/home/runner/entrypoint.sh`;
the orchestrator pins the runner Pod's `command` to that path). See the
"Choosing runner images (and bringing your own)" section in
[`install.md`](install.md) — the contract is backend-independent.

---

## 6. Pin image digests

The chart retains digest-pinned legacy 2.1.10 images. Shared mode requires
explicit 2.2+ release-manifest values; override controller, proxy and terminal
runner digests together before installing. The zero digests earlier in this
guide are placeholders and cannot run. Resolve the intended approved release
manifest instead of assuming the chart's `appVersion` replaces its image pins:

```sh
# Fetch digests for each image
for img in orchestrator proxy socket-proxy; do
  docker buildx imagetools inspect \
    ghcr.io/andend-collective/runsecure/${img}:2.2.0 \
    --format '{{.Manifest.Digest}}'
done
```

Update `image.orchestrator.digest`, `image.proxy.digest`, and
`image.socketProxy.digest` in your values file, then upgrade:

The chart binds the rendered scope ConfigMap to the controller Pod template with
its managed `checksum/scope-config` annotation. A Helm upgrade that changes
approved policy, enrollment, runner images or placement restarts the singleton
controller through the existing `Recreate` strategy and drain window. User Pod
annotations are preserved; this managed checksum cannot be overridden. Declaring
`runnerConfig`, `runnerImage` or project `kubernetes` settings requires explicit
namespace enrollment for every repository; omitting all shared settings retains
legacy repository policy loading. TCP egress cannot use Squid's port 3128, or
port 53 when `dns.host: false` activates dnsmasq.

```sh
helm upgrade runsecure-production charts/runsecure-orchestrator/ \
  -f my-scope-values.yaml \
  -n runsecure-production
```

Digest takes precedence over tag in the chart's pod spec.

---

## 7. How runner policy is loaded

Shared mode loads approved `runnerConfig` from the mounted scope ConfigMap and
never fetches repository policy. In legacy single-namespace Kubernetes mode, the orchestrator fetches each repo's
`.github/runner.yml` from the GitHub API (using the authenticated credential)
rather than reading it from a bind-mounted project directory. The `project_dir`
field in the scope config is not used on the Kubernetes backend; only the
`repo` and `max_concurrent` fields are required.

The orchestrator caches the `runner.yml` ETag per repo to avoid redundant API
calls on every poll tick. The rendered egress configs (Squid, HAProxy, optional
dnsmasq) are written into the per-spawn Secret and mounted into the proxy Pod.

---

## 8. TLS (optional)

The Kubernetes backend talks directly to the Kubernetes API using its normal
TLS and ServiceAccount credentials. It has no Docker socket-proxy hop. The
optional certificate resources remain available for compatibility; enabling
`tls.enabled` does not add a separate runner or controller mTLS channel. The
socket-proxy TLS 1.3 feature applies to Compose deployments.

```yaml
tls:
  enabled: true
  selfSigned: true           # cert-manager self-signed Issuer
  secretName: runsecure-orchestrator-tls
  dnsNames:
    - runsecure-orchestrator.runsecure-production.svc
```

With `selfSigned: true`, the chart emits a cert-manager `Issuer` and
`Certificate`. With `selfSigned: false`, set `issuerName` to the name of an
existing `Issuer` or `ClusterIssuer`.

cert-manager must be installed in the cluster when `tls.enabled: true`. The
`Certificate` and `Issuer` templates render only when the flag is set; no
cert-manager CRDs are required for a plaintext deployment.

---

## 9. Verify

Check that the orchestrator is running and healthy:

```sh
kubectl -n runsecure-production get pods
# NAME                                    READY   STATUS    RESTARTS
# runsecure-production-orch-xxxx-yyyy     1/1     Running   0

kubectl -n runsecure-production port-forward \
  svc/runsecure-production-runsecure-orchestrator 8080:8080 8081:8081 &
curl -sf http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl -sf http://127.0.0.1:8080/readyz
curl -sf http://127.0.0.1:8081/metrics | grep in_flight
# runsecure_orchestrator_in_flight_runners{...} 0
```

Trigger a spawn with a workflow targeting the approved labels (`runnerConfig`
in shared mode, `runner.yml` in legacy mode).
Watch the orchestrator logs for the spawn sequence:

```sh
kubectl -n runsecure-production logs -f deployment/runsecure-production-runsecure-orchestrator \
  | jq -c 'select(.["event.sub.type"]?)'
```

Expected events in order:

```
runsecure.orchestrator.poll.tick
runsecure.orchestrator.poll.queued_jobs_observed
runsecure.orchestrator.spawn.started
runsecure.orchestrator.spawn.jit_acquired
runsecure.orchestrator.spawn.runner_created
runsecure.orchestrator.spawn.completed
```

---

## 10. Run the integration tests

The `tests/integration/k8s/run-k8s-tests.sh` harness proves the security
claims on a real cluster (kind + Calico):

```sh
./tests/integration/k8s/run-k8s-tests.sh
```

The harness:

1. Creates a kind cluster with Calico (NetworkPolicy-enforcing CNI;
   disableDefaultCNI=true in kind config so kindnet is never installed).
2. Applies PSS Restricted labels on the test namespace and asserts a
   privileged Pod is rejected.
3. Deploys a two-spawn stack (spawn01 + spawn02) with NetworkPolicies and
   asserts:
   - Runner → own proxy (3128/TCP): succeeds.
   - Runner → internet (1.1.1.1:80): blocked.
   - Runner → kube-apiserver: blocked.
   - Runner (spawn01) → spawn02 proxy: blocked (cross-spawn isolation).
4. Applies the chart RBAC, performs a real namespace-scoped NetworkPolicy
   create/delete as the orchestrator SA, and proves that SA cannot create
   Namespaces or ClusterRoles and cannot act in `kube-system`.
5. Runs the generated runner-object contract (including CPU/memory and `/tmp`
   bounds), then `helm template` + `helm install --dry-run` against the chart.

Prerequisites: `kind`, `kubectl`, `helm`, and `go` in PATH. If any are absent the
harness exits 0 (SKIP) rather than failing.

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Orchestrator exits immediately | Missing or wrong Secret name for auth | Check `kubectl -n runsecure-<scope> get secret`; verify the key name (`pat` or `private-key`). |
| Auth file mode error | Incorrect Secret projection permissions | Kubernetes requires 0440 with fsGroup readability; Compose requires 0400. |
| No pods spawned; many `auth.degraded` events | PAT/App lacks Administration:RW for a repo | Re-issue with correct permissions. |
| Runner Pod stuck Pending | PSS admission rejecting the Pod | Check `kubectl describe pod <name> -n runsecure-<scope>` for `violates PodSecurity`; ensure the image runs as UID 1001 with no capabilities. |
| Runner cannot reach proxy | NetworkPolicy not enforced by CNI | Verify the cluster's CNI enforces NetworkPolicy (kindnet/flannel do not). |
| `NetworkPolicy VIOLATION` in k8s tests | `ProxyIngressNetworkPolicy` missing or misconfigured | This policy is load-bearing — without it the default-deny blocks runner→proxy even when RunnerEgressNetworkPolicy allows it. Check all three per-spawn policies are present. |
| Breaker stuck open (no spawns) | 5 consecutive spawn failures | `kubectl logs ... \| grep breaker.opened` — fix upstream cause; breaker enters half-open after 5 min cooldown. |

---

## 12. Security model (Kubernetes backend)

The Kubernetes backend uses runtime-default seccomp and its own resource and
network controls. The controller NetworkPolicy permits exact API/DNS peers and
external IPv4 TCP80/443; `orch_egress.allow_domains` is not domain enforcement on the
controller. Runner proxy domain policy is separate. Controls are exercised by
`tests/integration/k8s/run-k8s-tests.sh` on Calico:

| Claim | Mechanism | Verified by |
|---|---|---|
| Runner can only resolve cluster DNS and reach its own proxy | `RunnerEgressNetworkPolicy` (runner → exact DNS Service `/32s` plus exact namespace/Pod-label-selected DNS Pods on 53, and same-spawn proxy on 3128/TCP) + `ProxyIngressNetworkPolicy` | `run-k8s-tests.sh` step 5a (both DNS peer forms plus DNS-named proxy connection) |
| Cross-spawn isolation | `ProxyIngressNetworkPolicy` pins `runsecure.io/spawn-id` in the From selector — spawn A's runner cannot reach spawn B's proxy | `run-k8s-tests.sh` step 5d |
| Orchestrator SA is namespace-scoped least-privilege | `Role` (not `ClusterRole`); verbs limited to `pods/services/secrets/networkpolicies` in the scope namespace | `run-k8s-tests.sh` step 6 (RBAC assertions) |
| Runner CPU, memory, and temporary storage are bounded | Equal CPU/memory Pod requests and limits from `runner.yml`; 512 MiB memory-backed `/tmp` | `run-k8s-tests.sh` step 7c (generated runner-object contract) |
| Process-count containment is an explicit cluster prerequisite | Kubernetes has no per-Pod PID-limit field; eligible nodes require bounded kubelet `podPidsLimit` | Deployment prerequisite review; Compose-only per-runner PID test |
| PSS Restricted admission | Namespace labeled `pod-security.kubernetes.io/enforce: restricted`; privileged Pods are rejected | `run-k8s-tests.sh` step 3 |
| ProxyIngressNetworkPolicy is load-bearing | Without it, the namespace default-deny blocks runner→proxy 3128/TCP even when the runner's egress rule matches; this was a real bug during development | Code comment in `kube/objects.go:ProxyIngressNetworkPolicy` |
| NetworkPolicy enforcement requires an enforcing CNI | kindnet/flannel ignore NetworkPolicy; Calico/Cilium enforce it | `kind-calico.yaml` (disableDefaultCNI=true; Calico installed) |
| GitHub App least-privilege tokens | Installation access tokens scoped to selected repos; auto-rotate; no user identity | `infra/orchestrator/internal/auth/githubapp.go` |
| Kubernetes API TLS | In-cluster API client uses ServiceAccount identity; Kubernetes mode has no Docker socket-proxy hop | `internal/kube/client.go:NewInCluster` |

For the full threat model and claim catalog, see [SECURITY.md](./SECURITY.md).
