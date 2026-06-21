# Installing the RunSecure Orchestrator (Kubernetes backend)

This guide walks through deploying the RunSecure orchestrator to an existing
Kubernetes cluster using the Helm chart at `charts/runsecure-orchestrator/`.
One Helm release = one scope. The orchestrator fetches `runner.yml` from
the GitHub API (no bind-mount) and spawns per-job runner+proxy Pod stacks
with namespace-scoped NetworkPolicies and RBAC.

For the Compose backend (Linux/macOS host with Docker), see
[`install.md`](install.md).

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
- **Helm ≥ 3.12**.

### Optional

- **cert-manager** — required only when `tls.enabled: true`. If you are not
  using TLS on the orchestrator→socket-proxy hop, cert-manager is not needed.

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

The orchestrator enforces that the private key file has mode 0400 — the
chart mounts it read-only from the Secret.

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
    tag: "2.1.0"
    # Replace with the real digest from the 2.1.0 release — see step 6.
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  proxy:
    repository: ghcr.io/andend-collective/runsecure/proxy
    tag: "2.1.0"
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  socketProxy:
    repository: ghcr.io/andend-collective/runsecure/socket-proxy
    tag: "2.1.0"
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

### Values reference

| Key | Default | Description |
|---|---|---|
| `scope.name` | `"default"` | Short lowercase name; becomes the k8s namespace `runsecure-<name>`. |
| `scope.backend` | `kube` | Must be `kube` for this chart. |
| `scope.globalMaxRunners` | `5` | Ceiling on concurrent runner Pods across all repos in the scope. |
| `scope.pollIntervalSeconds` | `15` | How often the orchestrator polls GitHub for queued jobs. Minimum 5. |
| `scope.securityProfile` | `strict` | `strict` \| `standard` \| `permissive`. Controls per-project override permissions. |
| `scope.repos` | `[]` | List of `{repo: owner/repo, maxConcurrent: N}` entries. |
| `auth.type` | `pat` | `pat` or `github_app`. |
| `auth.pat.existingSecretName` | `""` | Name of a pre-existing Secret with key `pat`. |
| `auth.app.appId` | `""` | GitHub App ID (string). |
| `auth.app.installationId` | `""` | GitHub App installation ID (string). |
| `auth.app.privateKeySecretName` | `""` | Name of a pre-existing Secret with key `private-key` (PEM). |
| `tls.enabled` | `false` | Enable mTLS on the orchestrator→socket-proxy hop. |
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
  `networkpolicies` verbs `create/get/list/watch/delete` in the scope
  namespace only.
- **Default-deny NetworkPolicy** — denies all ingress and egress to every
  Pod in the namespace; two allow policies carve out only what the
  orchestrator needs (kube-apiserver, kube-dns, external HTTPS for GitHub).
- **ConfigMap** with the rendered scope config.
- **Orchestrator Deployment** (single replica; distroless, non-root UID 1001,
  `cap_drop: ALL`, read-only root filesystem, `seccompProfile: RuntimeDefault`).
- **Service** exposing `/healthz` and `/metrics` on port 8080 (ClusterIP only;
  not externally accessible).
- (Conditional) **Certificate + Issuer** when `tls.enabled: true`.

### Per-spawn objects (created at runtime, not by Helm)

For each CI job the orchestrator spawns:

- **Secret** — carries the GitHub JIT runner config and rendered Squid/HAProxy
  egress configs. Acts as the owning object; deleting it cascades GC to all
  other spawn resources.
- **ClusterIP Service** — proxy's stable DNS name inside the namespace.
- **NetworkPolicies** (3 per spawn):
  - `RunnerEgressNetworkPolicy` — runner → proxy on port 3128 only; all other
    egress blocked.
  - `ProxyEgressNetworkPolicy` — proxy → kube-dns (53/UDP+TCP) + internet
    (via Squid allow-list at L7).
  - `ProxyIngressNetworkPolicy` — only this spawn's runner Pod may connect to
    this spawn's proxy. Cross-spawn connections are blocked by pinning both the
    target (`runsecure.io/role=proxy`) and source (`runsecure.io/role=runner`)
    selectors to the same `runsecure.io/spawn-id`. This policy is load-bearing:
    without it, the namespace default-deny blocks runner→proxy connections even
    when the runner has a matching egress rule.
- **Proxy Pod** — runs Squid + HAProxy + optional dnsmasq. Receives egress
  configs from the Secret mount.
- **Runner Pod** — the hardened GitHub Actions runner. `HTTP_PROXY` is set to
  the proxy Service DNS name; the runner has no other network path.

All per-spawn Pods run with the same securityContext as the orchestrator
itself (PSS Restricted, `runAsUser: 1001`, `cap_drop: ALL`,
`readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`).

---

## 6. Pin image digests

The chart ships placeholder digests (`sha256:000...`). Replace them with the
real 2.1.0 digests before deploying to a non-test cluster:

```sh
# Fetch digests for each image
for img in orchestrator proxy socket-proxy; do
  docker buildx imagetools inspect \
    ghcr.io/andend-collective/runsecure/${img}:2.1.0 \
    --format '{{.Manifest.Digest}}'
done
```

Update `image.orchestrator.digest`, `image.proxy.digest`, and
`image.socketProxy.digest` in your values file, then upgrade:

```sh
helm upgrade runsecure-production charts/runsecure-orchestrator/ \
  -f my-scope-values.yaml \
  -n runsecure-production
```

Digest takes precedence over tag in the chart's pod spec.

---

## 7. How runner.yml is fetched

On the Kubernetes backend, the orchestrator fetches each repo's
`.github/runner.yml` from the GitHub API (using the authenticated credential)
rather than reading it from a bind-mounted project directory. The `project_dir`
field in the scope config is not used on the Kubernetes backend; only the
`repo` field is required.

The orchestrator caches the `runner.yml` ETag per repo to avoid redundant API
calls on every poll tick. The rendered egress configs (Squid, HAProxy, optional
dnsmasq) are written into the per-spawn Secret and mounted into the proxy Pod.

---

## 8. TLS (optional)

The optional mTLS mode secures the orchestrator→socket-proxy hop with TLS 1.3,
`RequireAndVerifyClientCert`. Enable it in your values:

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
  svc/runsecure-production-runsecure-orchestrator 8080:8080 &
curl -sf http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl -sf http://127.0.0.1:8080/metrics | grep in_flight
# runsecure_orchestrator_in_flight_runners{...} 0
```

Trigger a spawn by pushing a workflow that targets labels from `runner.yml`.
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
4. Applies the chart RBAC via `helm template` and asserts the orchestrator SA
   cannot create ClusterRoles and cannot act in `kube-system`.
5. Runs `helm template` + `helm install --dry-run` against the chart.

Prerequisites: `kind`, `kubectl`, `helm` in PATH. If any are absent the
harness exits 0 (SKIP) rather than failing.

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Orchestrator exits immediately | Missing or wrong Secret name for auth | Check `kubectl -n runsecure-<scope> get secret`; verify the key name (`pat` or `private-key`). |
| `auth: private key file mode must be 0400` | Secret was created with wrong permissions | Re-create the Secret; the chart mounts it read-only with mode 0400. |
| No pods spawned; many `auth.degraded` events | PAT/App lacks Administration:RW for a repo | Re-issue with correct permissions. |
| Runner Pod stuck Pending | PSS admission rejecting the Pod | Check `kubectl describe pod <name> -n runsecure-<scope>` for `violates PodSecurity`; ensure the image runs as UID 1001 with no capabilities. |
| Runner cannot reach proxy | NetworkPolicy not enforced by CNI | Verify the cluster's CNI enforces NetworkPolicy (kindnet/flannel do not). |
| `NetworkPolicy VIOLATION` in k8s tests | `ProxyIngressNetworkPolicy` missing or misconfigured | This policy is load-bearing — without it the default-deny blocks runner→proxy even when RunnerEgressNetworkPolicy allows it. Check all three per-spawn policies are present. |
| Breaker stuck open (no spawns) | 5 consecutive spawn failures | `kubectl logs ... \| grep breaker.opened` — fix upstream cause; breaker enters half-open after 5 min cooldown. |

---

## 12. Security model (Kubernetes backend)

The Kubernetes backend enforces the same defense layers as the Compose
backend plus k8s-specific controls. Each claim is verified by
`tests/integration/k8s/run-k8s-tests.sh` on Calico:

| Claim | Mechanism | Verified by |
|---|---|---|
| Runner can only reach its own proxy | `RunnerEgressNetworkPolicy` (runner → proxy 3128/TCP only) + `ProxyIngressNetworkPolicy` (proxy accepts only from same-spawn runner) | `run-k8s-tests.sh` step 5 (NetworkPolicy assertions) |
| Cross-spawn isolation | `ProxyIngressNetworkPolicy` pins `runsecure.io/spawn-id` in the From selector — spawn A's runner cannot reach spawn B's proxy | `run-k8s-tests.sh` step 5d |
| Orchestrator SA is namespace-scoped least-privilege | `Role` (not `ClusterRole`); verbs limited to `pods/services/secrets/networkpolicies` in the scope namespace | `run-k8s-tests.sh` step 6 (RBAC assertions) |
| PSS Restricted admission | Namespace labeled `pod-security.kubernetes.io/enforce: restricted`; privileged Pods are rejected | `run-k8s-tests.sh` step 3 |
| ProxyIngressNetworkPolicy is load-bearing | Without it, the namespace default-deny blocks runner→proxy 3128/TCP even when the runner's egress rule matches; this was a real bug during development | Code comment in `kube/objects.go:ProxyIngressNetworkPolicy` |
| NetworkPolicy enforcement requires an enforcing CNI | kindnet/flannel ignore NetworkPolicy; Calico/Cilium enforce it | `kind-calico.yaml` (disableDefaultCNI=true; Calico installed) |
| GitHub App least-privilege tokens | Installation access tokens scoped to selected repos; auto-rotate; no user identity | `infra/orchestrator/internal/auth/githubapp.go` |
| Optional mTLS on socket-proxy hop | TLS 1.3, `RequireAndVerifyClientCert`; cert-manager `Certificate` when `tls.enabled: true` | `infra/socket-proxy/internal/config/config.go:BuildTLSConfig` |

For the full threat model and claim catalog, see [SECURITY.md](./SECURITY.md).
