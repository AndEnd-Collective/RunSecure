#!/usr/bin/env bash
# run-k8s-tests.sh — kind+Calico integration test harness for RunSecure k8s backend.
#
# Proves the security model on a REAL cluster:
#   1. PSS Restricted admission rejects privileged pods
#   2. NetworkPolicy: runner can ONLY reach its proxy (not internet, not apiserver,
#      not a different spawn's proxy)
#   3. RBAC: least-privilege SA can perform runtime policy reconciliation in
#      its namespace but cannot create namespaces/clusterroles or act elsewhere
#   4. Helm/runtime: chart renders and generated runners retain resource bounds
#
# SKIP (exit 0) if kind/kubectl/helm/go are absent.
# FAIL loudly (exit 1) on any security violation.
#
# Usage:
#   ./tests/integration/k8s/run-k8s-tests.sh
#   SKIP_CLEANUP=1 ./tests/integration/k8s/run-k8s-tests.sh  # keep cluster for debugging

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
CLUSTER_NAME="rs-itest"
NS="runsecure-itest"
SA_NAME="rs-itest-runsecure-orchestrator"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/manifests"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Calico v3.29.3 — monolithic manifest (no tigera-operator).
# The operator approach fails on k8s >=1.30 because installations.operator.tigera.io
# CRD annotation exceeds the 262144-byte k8s limit. The monolithic calico.yaml
# installs Calico as DaemonSets directly — no operator, no size-limit issue.
# Pod CIDR is patched to 192.168.0.0/16 to match kind-calico.yaml.
CALICO_VERSION="v3.29.3"
CALICO_MANIFEST_URL="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

PASS=0
FAIL=0

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[k8s-test] $*"; }
pass() { PASS=$((PASS + 1)); echo "[PASS] $*"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $*"; }

# assert_succeeds <description> <cmd...>
assert_succeeds() {
  local desc="$1"; shift
  if "$@" 2>/dev/null; then
    pass "${desc}"
  else
    fail "${desc} — command failed: $*"
  fi
}

# assert_fails <description> <cmd...>
assert_fails() {
  local desc="$1"; shift
  if "$@" 2>/dev/null; then
    fail "${desc} — expected failure but command SUCCEEDED: $*"
  else
    pass "${desc}"
  fi
}

# wait_for_pod_ready <namespace> <pod-name> <timeout-seconds>
wait_for_pod_ready() {
  local ns="$1" pod="$2" timeout="$3"
  log "Waiting up to ${timeout}s for pod ${ns}/${pod} to be Running..."
  kubectl wait --for=condition=Ready pod/"${pod}" -n "${ns}" --timeout="${timeout}s" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# Prerequisite check — SKIP if tools are absent
# ─────────────────────────────────────────────────────────────────────────────
for tool in kind kubectl helm go; do
  if ! command -v "${tool}" &>/dev/null; then
    log "SKIP: ${tool} not found in PATH — skipping k8s integration tests"
    exit 0
  fi
done
log "Prerequisites: kind $(kind version --short 2>/dev/null || kind version), kubectl $(kubectl version --client --short 2>/dev/null | head -1), helm $(helm version --short 2>/dev/null)"

# ─────────────────────────────────────────────────────────────────────────────
# Trap: always tear down the cluster on EXIT (unless SKIP_CLEANUP=1)
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
  if [[ "${SKIP_CLEANUP:-0}" == "1" ]]; then
    log "SKIP_CLEANUP=1 — cluster '${CLUSTER_NAME}' left running for debugging"
    return
  fi
  log "Tearing down kind cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Create kind cluster + install Calico
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 1: Creating kind cluster '${CLUSTER_NAME}' (disableDefaultCNI=true) ==="

# Delete any stale cluster from a previous interrupted run
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true

# Do NOT use --wait: with disableDefaultCNI=true, nodes never reach Ready
# until we install Calico — so --wait would time out. We wait for nodes
# explicitly after Calico is installed.
kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/kind-calico.yaml"
log "Cluster created. Switching kubectl context..."
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

log "Installing Calico ${CALICO_VERSION} (monolithic calico.yaml, podSubnet=192.168.0.0/16)..."
# The calico.yaml manifest uses CALICO_IPV4POOL_CIDR env var to set the pod CIDR.
# Default is 192.168.0.0/16 which matches our kind config — no patching needed.
# Apply and tolerate already-exists errors (idempotent).
kubectl apply -f "${CALICO_MANIFEST_URL}" 2>&1 | grep -v "^Warning:" || true

log "Waiting for calico-node DaemonSet pods to be ready (up to 6 minutes)..."
# calico-node DaemonSet is in kube-system in the monolithic manifest
kubectl rollout status daemonset/calico-node -n kube-system --timeout=360s

log "Waiting for calico-kube-controllers to be ready..."
kubectl rollout status deployment/calico-kube-controllers -n kube-system --timeout=120s 2>/dev/null || true

# Wait for nodes to become Ready (CNI required for node Ready condition)
log "Waiting for all nodes to be Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

log "Calico + nodes ready."

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Create namespace with PSS Restricted labels
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 2: Creating namespace ${NS} with PSS Restricted labels ==="
kubectl apply -f "${MANIFESTS}/namespace.yaml"
kubectl get namespace "${NS}" -o yaml | grep pod-security || true

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: PSS assertion — privileged pod MUST be rejected
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 3: PSS assertion ==="
log "Applying privileged pod — must be rejected by PSS Restricted admission..."

# Capture both exit code and error output
PSS_OUTPUT=$(kubectl apply -f "${MANIFESTS}/pss-violation-pod.yaml" 2>&1) || PSS_EXIT=$?
PSS_EXIT="${PSS_EXIT:-0}"

if [[ "${PSS_EXIT}" -ne 0 ]] && echo "${PSS_OUTPUT}" | grep -qi "violates.*PodSecurity\|forbidden.*PodSecurity\|admission webhook\|pod security"; then
  pass "PSS: privileged pod rejected with 'violates PodSecurity' (exit ${PSS_EXIT})"
elif [[ "${PSS_EXIT}" -ne 0 ]]; then
  pass "PSS: privileged pod rejected (exit ${PSS_EXIT}) — output: ${PSS_OUTPUT}"
else
  fail "PSS: privileged pod was ADMITTED — PSS Restricted not enforced. Output: ${PSS_OUTPUT}"
fi

# Ensure the violation pod doesn't linger
kubectl delete pod pss-violation-test -n "${NS}" --ignore-not-found 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Deploy proxy pod + service, runner pod, NetworkPolicies
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 4: Deploying spawn01 stack (proxy + runner + NetworkPolicies) ==="
kubectl apply -f "${MANIFESTS}/networkpolicies.yaml"
kubectl apply -f "${MANIFESTS}/proxy-pod.yaml"
kubectl apply -f "${MANIFESTS}/proxy-service.yaml"
kubectl apply -f "${MANIFESTS}/runner-pod.yaml"

# Deploy spawn02 attacker proxy for cross-spawn isolation test
kubectl apply -f "${MANIFESTS}/attacker-pod.yaml"
kubectl apply -f "${MANIFESTS}/api-peer-pods.yaml"

log "Waiting for proxy pod rs-proxy-spawn01 to be Ready..."
wait_for_pod_ready "${NS}" "rs-proxy-spawn01" 120

log "Waiting for runner pod rs-runner-spawn01 to be Ready..."
wait_for_pod_ready "${NS}" "rs-runner-spawn01" 120

log "Waiting for attacker proxy rs-proxy-spawn02 to be Ready..."
wait_for_pod_ready "${NS}" "rs-proxy-spawn02" 120

log "Waiting for exact-pair API policy probes to be Ready..."
wait_for_pod_ready default "rs-api-peer-one" 120
wait_for_pod_ready default "rs-api-peer-two" 120

# Give Calico policy programming time to propagate (DataPath convergence)
log "Sleeping 10s for Calico NetworkPolicy programming to converge..."
sleep 10

# Resolve ClusterIPs before NetworkPolicy assertions. The own-proxy assertion
# intentionally uses the Service DNS name so the test proves both the exact
# cluster-DNS /32 rule and the same-spawn proxy path.
PROXY_SVC_IP=$(kubectl get svc rs-proxy-svc-spawn01 -n "${NS}" \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
PROXY_SVC2_IP=$(kubectl get svc rs-proxy-svc-spawn02 -n "${NS}" \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
APISERVER_IP=$(kubectl get svc kubernetes -n default \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "10.96.0.1")
APISERVER_ENDPOINT_IP=$(kubectl get endpoints kubernetes -n default \
  -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || echo "")
APISERVER_ENDPOINT_PORT=$(kubectl get endpoints kubernetes -n default \
  -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null || echo "")
DNS_SERVICE_IP=$(kubectl get svc kube-dns -n kube-system \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
DNS_POD_IP=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
  -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
API_PEER_ONE_IP=$(kubectl get pod rs-api-peer-one -n default \
  -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")
API_PEER_TWO_IP=$(kubectl get pod rs-api-peer-two -n default \
  -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")

log "Resolved: proxy-svc=${PROXY_SVC_IP}, proxy-svc2=${PROXY_SVC2_IP}, apiserver-service=${APISERVER_IP}:443, apiserver-endpoint=${APISERVER_ENDPOINT_IP}:${APISERVER_ENDPOINT_PORT}, dns-service=${DNS_SERVICE_IP}, dns-pod=${DNS_POD_IP}, pair-probes=${API_PEER_ONE_IP}:8443/${API_PEER_TWO_IP}:9443"

if [[ -z "${PROXY_SVC_IP}" ]]; then
  fail "Could not resolve ClusterIP for rs-proxy-svc-spawn01 — cannot run NetworkPolicy assertions"
fi
if [[ -z "${APISERVER_ENDPOINT_IP}" || -z "${APISERVER_ENDPOINT_PORT}" ]]; then
  fail "Could not resolve the Kubernetes API endpoint — cannot prove post-DNAT policy"
fi
if [[ -z "${DNS_SERVICE_IP}" || -z "${DNS_POD_IP}" ]]; then
  fail "Could not resolve both cluster DNS Service and Pod peers"
fi
if [[ -z "${API_PEER_ONE_IP}" || -z "${API_PEER_TWO_IP}" ]]; then
  fail "Could not resolve exact-pair policy probe Pod IPs"
fi

HELM_NETWORK_ARGS=(
  --set-string "kubernetesNetwork.apiServerPeers[0].cidr=${APISERVER_IP}/32"
  --set "kubernetesNetwork.apiServerPeers[0].port=443"
  --set-string "kubernetesNetwork.apiServerPeers[1].cidr=${APISERVER_ENDPOINT_IP}/32"
  --set "kubernetesNetwork.apiServerPeers[1].port=${APISERVER_ENDPOINT_PORT}"
  --set-string "kubernetesNetwork.apiServerPeers[2].cidr=${API_PEER_ONE_IP}/32"
  --set "kubernetesNetwork.apiServerPeers[2].port=8443"
  --set-string "kubernetesNetwork.apiServerPeers[3].cidr=${API_PEER_TWO_IP}/32"
  --set "kubernetesNetwork.apiServerPeers[3].port=9443"
  --set-string "kubernetesNetwork.dnsServiceCIDRs[0]=${DNS_SERVICE_IP}/32"
)

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: NetworkPolicy assertions
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 5: NetworkPolicy assertions ==="

# 5a. Runner → proxy (spawn01) through its Service DNS name MUST succeed.
PROXY_SVC_DNS="rs-proxy-svc-spawn01.${NS}.svc"
log "5a. runner → own proxy DNS (${PROXY_SVC_DNS}:3128) — MUST succeed..."
if kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
    nc -z -w 10 "${PROXY_SVC_DNS}" 3128 2>/dev/null; then
  pass "NetworkPolicy: runner resolved and reached own proxy at ${PROXY_SVC_DNS}:3128"
else
  fail "NetworkPolicy: runner CANNOT resolve/reach own proxy at ${PROXY_SVC_DNS}:3128"
fi

RUNNER_DNS_SERVICE_RESULT=$(kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
  dig +time=5 +tries=1 +short @"${DNS_SERVICE_IP}" kubernetes.default.svc.cluster.local 2>/dev/null || echo "")
RUNNER_DNS_POD_RESULT=$(kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
  dig +time=5 +tries=1 +short @"${DNS_POD_IP}" kubernetes.default.svc.cluster.local 2>/dev/null || echo "")
if [[ -n "${RUNNER_DNS_SERVICE_RESULT}" && -n "${RUNNER_DNS_POD_RESULT}" ]]; then
  pass "NetworkPolicy: runner reaches exact pre-DNAT DNS Service and post-DNAT DNS Pod peers"
else
  fail "NetworkPolicy: runner cannot reach both exact DNS Service and Pod peers"
fi

# 5b. Runner → internet (1.1.1.1) MUST fail (blocked by default-deny + RunnerEgress only allows proxy)
log "5b. runner → 1.1.1.1 (internet) — MUST be blocked..."
if kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
    nc -z -w 5 1.1.1.1 80 2>/dev/null; then
  fail "NetworkPolicy VIOLATION: runner reached internet (1.1.1.1:80) — should be blocked"
else
  pass "NetworkPolicy: runner blocked from internet (1.1.1.1:80)"
fi

# 5c. Runner → kubernetes API server MUST fail
log "5c. runner → API server (${APISERVER_IP}:443) — MUST be blocked..."
if kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
    nc -z -w 5 "${APISERVER_IP}" 443 2>/dev/null; then
  fail "NetworkPolicy VIOLATION: runner reached API server (${APISERVER_IP}:443) — should be blocked"
else
  pass "NetworkPolicy: runner blocked from API server (${APISERVER_IP}:443)"
fi

# 5d. Cross-spawn isolation: runner (spawn01) → spawn02 proxy ClusterIP on 3128 MUST fail.
# RunnerEgressNetworkPolicy uses spawn-id=spawn01 label selector — spawn02's Service IP
# maps to spawn02's proxy pod which has spawn-id=spawn02, so the policy blocks it.
log "5d. runner (spawn01) → spawn02 proxy (${PROXY_SVC2_IP}:3128) — MUST be blocked (cross-spawn isolation)..."
if kubectl exec rs-runner-spawn01 -n "${NS}" -c runner -- \
    nc -z -w 5 "${PROXY_SVC2_IP}" 3128 2>/dev/null; then
  fail "NetworkPolicy VIOLATION: runner (spawn01) reached spawn02's proxy — cross-spawn isolation broken"
else
  pass "NetworkPolicy: cross-spawn isolation holds (spawn01 runner cannot reach spawn02 proxy at ${PROXY_SVC2_IP})"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: RBAC assertions
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 6: RBAC assertions ==="

# Render the chart RBAC resources and apply them to get the SA + Role + RoleBinding
log "Rendering chart RBAC via helm template..."
CHART_DIR="${SCRIPT_DIR}/../../../charts/runsecure-orchestrator"
HELM_RBAC_MANIFEST=$(helm template rs-itest "${CHART_DIR}" \
  -f "${MANIFESTS}/helm-test-values.yaml" \
  --set scope.name=itest \
  -s templates/serviceaccount.yaml \
  -s templates/rbac.yaml 2>/dev/null)

if [[ -z "${HELM_RBAC_MANIFEST}" ]]; then
  fail "RBAC: helm template produced empty output"
else
  echo "${HELM_RBAC_MANIFEST}" | kubectl apply -f - 2>/dev/null && \
    pass "RBAC: helm-rendered SA + Role + RoleBinding applied successfully" || \
    fail "RBAC: failed to apply helm-rendered RBAC objects"
fi

# Derive SA name from helm template output (release=rs-itest, chart=runsecure-orchestrator)
SA_FQDN="system:serviceaccount:${NS}:${SA_NAME}"

# 6a. CAN create pods in own namespace
log "6a. SA can create pods in ${NS} — MUST succeed..."
if kubectl auth can-i create pods \
    --as="${SA_FQDN}" \
    -n "${NS}" 2>/dev/null | grep -q "^yes"; then
  pass "RBAC: SA can create pods in ${NS}"
else
  fail "RBAC: SA CANNOT create pods in ${NS} — RBAC binding missing or wrong"
fi

# 6b. CAN create services in own namespace
log "6b. SA can create services in ${NS} — MUST succeed..."
if kubectl auth can-i create services \
    --as="${SA_FQDN}" \
    -n "${NS}" 2>/dev/null | grep -q "^yes"; then
  pass "RBAC: SA can create services in ${NS}"
else
  fail "RBAC: SA CANNOT create services in ${NS}"
fi

# 6c. CAN create secrets in own namespace
log "6c. SA can create secrets in ${NS} — MUST succeed..."
if kubectl auth can-i create secrets \
    --as="${SA_FQDN}" \
    -n "${NS}" 2>/dev/null | grep -q "^yes"; then
  pass "RBAC: SA can create secrets in ${NS}"
else
  fail "RBAC: SA CANNOT create secrets in ${NS}"
fi

# 6d. CAN create networkpolicies in own namespace
log "6d. SA can create networkpolicies in ${NS} — MUST succeed..."
if kubectl auth can-i create networkpolicies \
    --as="${SA_FQDN}" \
    -n "${NS}" 2>/dev/null | grep -q "^yes"; then
  pass "RBAC: SA can create networkpolicies in ${NS}"
else
  fail "RBAC: SA CANNOT create networkpolicies in ${NS}"
fi

# 6e. Exercise the runtime's actual namespace-scoped reconciliation operation,
# not only an authorization query. This is the sole API create performed by
# EnsureDefaultDenyPolicy after Helm has provisioned the namespace.
log "6e. SA can create and delete a reconciliation NetworkPolicy — MUST succeed..."
if kubectl create --as="${SA_FQDN}" -f - >/dev/null 2>&1 <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rs-runtime-reconcile-check
  namespace: ${NS}
spec:
  podSelector:
    matchLabels:
      runsecure.io/runtime-reconcile-check: "true"
  policyTypes:
    - Ingress
    - Egress
EOF
then
  if kubectl delete networkpolicy rs-runtime-reconcile-check \
      --as="${SA_FQDN}" -n "${NS}" --wait=true >/dev/null 2>&1; then
    pass "RBAC: chart SA performed namespace-scoped runtime policy reconciliation"
  else
    fail "RBAC: chart SA created but could not delete reconciliation policy"
  fi
else
  fail "RBAC: chart SA could not perform runtime policy reconciliation"
fi

# 6f. CANNOT create namespaces. Helm owns the scope Namespace; granting this
# cluster-scoped privilege would violate the chart's least-privilege contract.
log "6f. SA cannot create namespaces — MUST be denied..."
if kubectl auth can-i create namespaces \
    --as="${SA_FQDN}" 2>/dev/null | grep -q "^yes"; then
  fail "RBAC VIOLATION: SA can create namespaces — over-privileged"
else
  pass "RBAC: SA cannot create namespaces (Helm owns namespace provisioning)"
fi

# 6g. CANNOT create clusterroles (cluster-scoped — no ClusterRole granted)
log "6g. SA cannot create clusterroles — MUST be denied..."
if kubectl auth can-i create clusterroles \
    --as="${SA_FQDN}" 2>/dev/null | grep -q "^yes"; then
  fail "RBAC VIOLATION: SA can create clusterroles — over-privileged"
else
  pass "RBAC: SA cannot create clusterroles (least-privilege confirmed)"
fi

# 6h. CANNOT create pods in kube-system (Role is namespace-scoped)
log "6h. SA cannot create pods in kube-system — MUST be denied..."
if kubectl auth can-i create pods \
    --as="${SA_FQDN}" \
    -n kube-system 2>/dev/null | grep -q "^yes"; then
  fail "RBAC VIOLATION: SA can create pods in kube-system — cross-namespace privilege"
else
  pass "RBAC: SA cannot create pods in kube-system (namespace-scoped Role confirmed)"
fi

# 6i. CANNOT delete nodes (cluster-scoped, not in role)
log "6i. SA cannot delete nodes — MUST be denied..."
if kubectl auth can-i delete nodes \
    --as="${SA_FQDN}" 2>/dev/null | grep -q "^yes"; then
  fail "RBAC VIOLATION: SA can delete nodes — dangerous cluster privilege"
else
  pass "RBAC: SA cannot delete nodes"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Helm assertions
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 7: Helm assertions ==="

# 7a. helm template succeeds (renders without errors)
log "7a. helm template renders without errors..."
if helm template rs-helm-test "${CHART_DIR}" \
    -f "${MANIFESTS}/helm-test-values.yaml" \
    --set scope.name=itest \
    "${HELM_NETWORK_ARGS[@]}" \
    --output-dir /tmp/rs-helm-render 2>/dev/null; then
  pass "Helm: chart template renders cleanly"
else
  fail "Helm: chart template failed to render"
fi

# 7b. helm install --dry-run succeeds against the live cluster
log "7b. helm install --dry-run against live cluster..."
# Use scope=dryrun so the chart targets namespace runsecure-dryrun, which does
# not already exist in the cluster (avoids namespace-already-exists conflict).
# --dry-run validates the rendered manifest against the live k8s API server.
if helm install rs-helm-dryrun "${CHART_DIR}" \
    -f "${MANIFESTS}/helm-test-values.yaml" \
    --set scope.name=dryrun \
    "${HELM_NETWORK_ARGS[@]}" \
    -n "runsecure-dryrun" \
    --create-namespace \
    --dry-run 2>/dev/null; then
  pass "Helm: dry-run install succeeded against live cluster"
else
  fail "Helm: dry-run install failed"
fi

# 7c. Runtime wiring parity: compile and execute the backend Spawn contract so
# generated runner Pods prove CPU/memory requests+limits, bounded /tmp, and no
# cluster-scoped Namespace API calls. Then inspect the rendered Deployment for
# immutable images, truthful readiness, and readable Secret projections.
log "7c. helm runtime wiring matches Kubernetes backend contract..."
if (cd "${REPO_ROOT}/infra/orchestrator" && \
    go test ./internal/backend/kube -run '^TestSpawn_CreatesAllObjects$' -count=1); then
  pass "Kubernetes runtime: generated runner resources are bounded and reconciliation is namespace-scoped"
else
  fail "Kubernetes runtime: generated runner resource/reconciliation contract failed"
fi
HELM_RUNTIME_MANIFEST=$(helm template rs-runtime "${CHART_DIR}" \
  -f "${MANIFESTS}/helm-test-values.yaml" \
  --set scope.name=itest \
  "${HELM_NETWORK_ARGS[@]}" 2>/dev/null || echo "")
RUNTIME_WIRING_OK=1
for name in RUNSECURE_PROXY_IMAGE RUNSECURE_RUNNER_IMAGE_DEFAULT \
  RUNSECURE_RUNNER_IMAGE_NODE RUNSECURE_RUNNER_IMAGE_PYTHON \
  RUNSECURE_RUNNER_IMAGE_RUST RUNSECURE_EGRESS_BASE_DIR \
  RUNSECURE_KUBE_API_SERVER_PEERS RUNSECURE_KUBE_DNS_SERVICE_CIDRS \
  RUNSECURE_KUBE_DNS_NAMESPACE RUNSECURE_KUBE_DNS_POD_LABEL_KEY \
  RUNSECURE_KUBE_DNS_POD_LABEL_VALUE; do
  if ! echo "${HELM_RUNTIME_MANIFEST}" | grep -q -- "- name: ${name}"; then
    RUNTIME_WIRING_OK=0
  fi
done
if echo "${HELM_RUNTIME_MANIFEST}" | grep -q 'DOCKER_HOST\|socket-proxy:2375'; then
  RUNTIME_WIRING_OK=0
fi

# 7d. Apply the chart-rendered policy to a Pod carrying the chart's actual
# orchestrator selector labels. This is a live Calico proof, not a static YAML
# assertion: DNS must survive Service DNAT and API traffic must survive either
# pre-DNAT (Service :443) or post-DNAT (endpoint port) policy evaluation.
log "7d. chart-selected orchestrator reaches exact cluster DNS and API peers..."
HELM_NETWORK_POLICY=$(helm template rs-itest "${CHART_DIR}" \
  -f "${MANIFESTS}/helm-test-values.yaml" \
  --set scope.name=itest \
  "${HELM_NETWORK_ARGS[@]}" \
  -s templates/networkpolicy-default-deny.yaml 2>/dev/null || echo "")
if [[ -z "${HELM_NETWORK_POLICY}" ]] ||
   ! echo "${HELM_NETWORK_POLICY}" | kubectl apply -f - >/dev/null; then
  fail "Helm: chart network policy could not be applied to live cluster"
else
  kubectl apply -f "${MANIFESTS}/orchestrator-network-pod.yaml" >/dev/null
  if wait_for_pod_ready "${NS}" "rs-orchestrator-network-test" 120 &&
     wait_for_pod_ready "${NS}" "rs-unlabelled-network-control" 120; then
    sleep 5
    if kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        getent hosts kubernetes.default.svc >/dev/null 2>&1; then
      pass "Helm NetworkPolicy: chart-selected orchestrator resolves cluster DNS"
    else
      fail "Helm NetworkPolicy: chart-selected orchestrator cannot resolve cluster DNS"
    fi
    ORCH_DNS_SERVICE_RESULT=$(kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
      dig +time=5 +tries=1 +short @"${DNS_SERVICE_IP}" kubernetes.default.svc.cluster.local 2>/dev/null || echo "")
    if [[ -n "${ORCH_DNS_SERVICE_RESULT}" ]]; then
      pass "Helm NetworkPolicy: pre-DNAT DNS Service /32 is reachable"
    else
      fail "Helm NetworkPolicy: pre-DNAT DNS Service /32 is not reachable"
    fi
    ORCH_DNS_POD_RESULT=$(kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
      dig +time=5 +tries=1 +short @"${DNS_POD_IP}" kubernetes.default.svc.cluster.local 2>/dev/null || echo "")
    if [[ -n "${ORCH_DNS_POD_RESULT}" ]]; then
      pass "Helm NetworkPolicy: post-DNAT DNS Pod selector is reachable"
    else
      fail "Helm NetworkPolicy: post-DNAT DNS Pod selector is not reachable"
    fi
    if kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 10 kubernetes.default.svc 443 >/dev/null 2>&1; then
      pass "Helm NetworkPolicy: chart-selected orchestrator reaches Kubernetes Service API"
    else
      fail "Helm NetworkPolicy: chart-selected orchestrator cannot reach Kubernetes Service API"
    fi
    if kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 10 "${APISERVER_ENDPOINT_IP}" "${APISERVER_ENDPOINT_PORT}" >/dev/null 2>&1; then
      pass "Helm NetworkPolicy: chart-selected orchestrator reaches post-DNAT API endpoint"
    else
      fail "Helm NetworkPolicy: chart-selected orchestrator cannot reach post-DNAT API endpoint"
    fi
    if kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 10 "${API_PEER_ONE_IP}" 8443 >/dev/null 2>&1 &&
       kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 10 "${API_PEER_TWO_IP}" 9443 >/dev/null 2>&1; then
      pass "Helm NetworkPolicy: both configured exact API probe pairs are reachable"
    else
      fail "Helm NetworkPolicy: a configured exact API probe pair is not reachable"
    fi
    if kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 5 "${API_PEER_ONE_IP}" 9443 >/dev/null 2>&1 ||
       kubectl exec rs-orchestrator-network-test -n "${NS}" -c network-test -- \
        nc -z -w 5 "${API_PEER_TWO_IP}" 8443 >/dev/null 2>&1; then
      fail "Helm NetworkPolicy VIOLATION: API CIDR/port cross-pair was reachable"
    else
      pass "Helm NetworkPolicy: API CIDR/port cross-pairs remain denied"
    fi
    if kubectl exec rs-unlabelled-network-control -n "${NS}" -c network-test -- \
        nc -z -w 5 "${APISERVER_IP}" 443 >/dev/null 2>&1; then
      fail "Helm NetworkPolicy VIOLATION: unlabelled control Pod reached Kubernetes API"
    else
      pass "Helm NetworkPolicy: unlabelled control Pod remains default-denied"
    fi
  else
    fail "Helm NetworkPolicy: network probe Pods did not become ready"
  fi
fi
if ! echo "${HELM_RUNTIME_MANIFEST}" | grep -q 'path: /readyz' ||
   ! echo "${HELM_RUNTIME_MANIFEST}" | grep -Eq 'defaultMode: (288|0440)' ||
   ! echo "${HELM_RUNTIME_MANIFEST}" | grep -q 'type: Recreate' ||
   ! echo "${HELM_RUNTIME_MANIFEST}" | grep -q 'terminationGracePeriodSeconds: 90'; then
  RUNTIME_WIRING_OK=0
fi
if [[ "${RUNTIME_WIRING_OK}" -eq 1 ]]; then
  pass "Helm: Kubernetes runtime wiring is Docker-free, immutable, readable, and readiness-aware"
else
  fail "Helm: Kubernetes runtime wiring contract is incomplete"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  k8s integration test results"
echo "  PASSED: ${PASS}"
echo "  FAILED: ${FAIL}"
echo "═══════════════════════════════════════════════════════════"

if [[ "${FAIL}" -gt 0 ]]; then
  echo "RESULT: FAILED — ${FAIL} security assertion(s) failed"
  exit 1
fi

echo "RESULT: PASSED — all ${PASS} assertions green"
exit 0
