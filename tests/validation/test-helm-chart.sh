#!/bin/bash
# ============================================================================
# RunSecure — Helm Chart CIS/PSS Assertions
# ============================================================================
# Validates charts/runsecure-orchestrator/ for:
#   - helm lint clean
#   - kubeconform -strict pass (kubernetes-version 1.29.0)
#   - PSS Restricted securityContext fields on every Pod template
#   - No ClusterRole / ClusterRoleBinding in rendered output
#   - No hostPath / hostNetwork / hostPID / hostIPC / privileged
#   - Default-deny NetworkPolicy present
#   - PSS enforce=restricted namespace label present
#   - Auth secret volume is root:fsGroup-readable 0440 (decimal 288), not world-readable
#   - Kube runtime image envs are immutable and no Docker dependency is injected
#   - Readiness, state, and writable egress paths match the runtime contract
#
# Run: bash tests/validation/test-helm-chart.sh
#
# Gracefully skips (exit 0) when helm or kubeconform is not installed so
# CI without those tools is not blocked. Fails with exit 1 when tools are
# present and an assertion fails.
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${RUNSECURE_ROOT}/charts/runsecure-orchestrator"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

pass()  { RESULTS+=("PASS: $1"); PASS=$((PASS + 1)); }
fail()  { RESULTS+=("FAIL: $1"); FAIL=$((FAIL + 1)); }
skip_test() { RESULTS+=("SKIP: $1"); SKIP=$((SKIP + 1)); }

# ── Tool availability checks ────────────────────────────────────────────────

HELM_BIN=""
KUBECONFORM_BIN=""

if command -v helm &>/dev/null; then
    HELM_BIN="$(command -v helm)"
fi
if command -v kubeconform &>/dev/null; then
    KUBECONFORM_BIN="$(command -v kubeconform)"
fi

# Try common non-PATH install locations.
if [[ -z "$KUBECONFORM_BIN" ]]; then
    for candidate in /usr/local/bin/kubeconform "${HOME}/.local/bin/kubeconform"; do
        if [[ -x "$candidate" ]]; then
            KUBECONFORM_BIN="$candidate"
            break
        fi
    done
fi

if [[ -z "$HELM_BIN" ]]; then
    echo "SKIP: helm not found — skipping helm chart assertions"
    exit 0
fi

if [[ -z "$KUBECONFORM_BIN" ]]; then
    skip_test "kubeconform not found — schema checks skipped; Helm runtime contract checks still run"
fi

# ── Helpers ─────────────────────────────────────────────────────────────────

# Render the chart with a representative sample scope so every template path
# is exercised with realistic values.
SAMPLE_VALUES=(
    "--set" "scope.name=ci-scope"
    "--set" "scope.securityProfile=strict"
    "--set" "scope.globalMaxRunners=3"
    "--set" "auth.type=pat"
    "--set" "auth.pat.value=ghp_placeholder"
)

render_chart() {
    "$HELM_BIN" template test-release "${CHART_DIR}" "${SAMPLE_VALUES[@]}" "$@"
}

# ── Test 1: helm lint ────────────────────────────────────────────────────────

if "$HELM_BIN" lint "${CHART_DIR}" &>/dev/null; then
    pass "helm lint charts/runsecure-orchestrator"
else
    fail "helm lint charts/runsecure-orchestrator — lint errors detected"
    "$HELM_BIN" lint "${CHART_DIR}" >&2 || true
fi

# ── Test 2: kubeconform (TLS disabled — baseline) ───────────────────────────

RENDERED_NO_TLS="$(render_chart 2>&1)" || {
    fail "helm template failed (tls.enabled=false): ${RENDERED_NO_TLS}"
    RENDERED_NO_TLS=""
}

if [[ -n "$RENDERED_NO_TLS" && -n "$KUBECONFORM_BIN" ]]; then
    KUBECONFORM_OUT="$(echo "${RENDERED_NO_TLS}" | \
        "${KUBECONFORM_BIN}" -strict -ignore-missing-schemas \
        -summary -kubernetes-version 1.29.0 2>&1)"
    if echo "${KUBECONFORM_OUT}" | grep -qE 'Invalid: [^0]|Errors: [^0]'; then
        fail "kubeconform (tls=false): validation errors — ${KUBECONFORM_OUT}"
    else
        pass "kubeconform -strict -kubernetes-version 1.29.0 (tls.enabled=false)"
    fi
fi
if [[ -n "$RENDERED_NO_TLS" && -z "$KUBECONFORM_BIN" ]]; then
    skip_test "kubeconform tls=false validation"
fi

# ── Test 3: kubeconform (TLS enabled + self-signed) ─────────────────────────

RENDERED_TLS="$(render_chart --set tls.enabled=true --set tls.selfSigned=true 2>&1)" || {
    fail "helm template failed (tls.enabled=true): ${RENDERED_TLS}"
    RENDERED_TLS=""
}

if [[ -n "$RENDERED_TLS" && -n "$KUBECONFORM_BIN" ]]; then
    KUBECONFORM_OUT_TLS="$(echo "${RENDERED_TLS}" | \
        "${KUBECONFORM_BIN}" -strict -ignore-missing-schemas \
        -summary -kubernetes-version 1.29.0 2>&1)"
    if echo "${KUBECONFORM_OUT_TLS}" | grep -qE 'Invalid: [^0]|Errors: [^0]'; then
        fail "kubeconform (tls=true): validation errors — ${KUBECONFORM_OUT_TLS}"
    else
        pass "kubeconform -strict -kubernetes-version 1.29.0 (tls.enabled=true + selfSigned)"
    fi
fi
if [[ -n "$RENDERED_TLS" && -z "$KUBECONFORM_BIN" ]]; then
    skip_test "kubeconform tls=true validation"
fi

# Use the no-TLS render for all remaining assertions (representative render).
RENDERED="${RENDERED_NO_TLS}"

if [[ -z "${RENDERED}" ]]; then
    echo ""
    echo "=== Helm Chart CIS/PSS Assertions ==="
    for r in "${RESULTS[@]}"; do echo "  $r"; done
    echo ""
    echo "FAILED: $PASS passed, $FAIL failed, $SKIP skipped"
    exit 1
fi

# ── Test 4: PSS Restricted — runAsNonRoot: true ──────────────────────────────

if echo "${RENDERED}" | grep -q 'runAsNonRoot: true'; then
    pass "PSS Restricted: runAsNonRoot: true present in pod securityContext"
else
    fail "PSS Restricted: runAsNonRoot: true NOT found in rendered output"
fi

# ── Test 5: PSS Restricted — runAsUser: 1001 ────────────────────────────────

if echo "${RENDERED}" | grep -q 'runAsUser: 1001'; then
    pass "PSS Restricted: runAsUser: 1001 present"
else
    fail "PSS Restricted: runAsUser: 1001 NOT found in rendered output"
fi

# ── Test 6: PSS Restricted — allowPrivilegeEscalation: false ────────────────

if echo "${RENDERED}" | grep -q 'allowPrivilegeEscalation: false'; then
    pass "PSS Restricted: allowPrivilegeEscalation: false present"
else
    fail "PSS Restricted: allowPrivilegeEscalation: false NOT found in rendered output"
fi

# ── Test 7: PSS Restricted — readOnlyRootFilesystem: true ───────────────────

if echo "${RENDERED}" | grep -q 'readOnlyRootFilesystem: true'; then
    pass "PSS Restricted: readOnlyRootFilesystem: true present"
else
    fail "PSS Restricted: readOnlyRootFilesystem: true NOT found in rendered output"
fi

# ── Test 8: PSS Restricted — capabilities drop ALL ──────────────────────────

if echo "${RENDERED}" | grep -qE '^\s*-\s*ALL\s*$'; then
    pass "PSS Restricted: capabilities drop ALL present"
else
    fail "PSS Restricted: 'drop: - ALL' NOT found in rendered output"
fi

# ── Test 9: PSS Restricted — seccompProfile RuntimeDefault ──────────────────

if echo "${RENDERED}" | grep -q 'type: RuntimeDefault'; then
    pass "PSS Restricted: seccompProfile type RuntimeDefault present"
else
    fail "PSS Restricted: seccompProfile type RuntimeDefault NOT found"
fi

# ── Test 10: No ClusterRole ───────────────────────────────────────────────────

if echo "${RENDERED}" | grep -qE '^kind:\s*ClusterRole$'; then
    fail "Security: ClusterRole found in rendered output — must use namespace-scoped Role only"
else
    pass "Security: no ClusterRole in rendered output"
fi

# ── Test 11: No ClusterRoleBinding ───────────────────────────────────────────

if echo "${RENDERED}" | grep -qE '^kind:\s*ClusterRoleBinding$'; then
    fail "Security: ClusterRoleBinding found in rendered output — must use namespace-scoped RoleBinding only"
else
    pass "Security: no ClusterRoleBinding in rendered output"
fi

# ── Test 12: No hostPath volumes ────────────────────────────────────────────

if echo "${RENDERED}" | grep -q 'hostPath:'; then
    fail "Security: hostPath volume found in rendered output"
else
    pass "Security: no hostPath volumes in rendered output"
fi

# ── Test 13: No hostNetwork ──────────────────────────────────────────────────

if echo "${RENDERED}" | grep -qE 'hostNetwork:\s*true'; then
    fail "Security: hostNetwork: true found in rendered output"
else
    pass "Security: no hostNetwork: true in rendered output"
fi

# ── Test 14: No hostPID ──────────────────────────────────────────────────────

if echo "${RENDERED}" | grep -qE 'hostPID:\s*true'; then
    fail "Security: hostPID: true found in rendered output"
else
    pass "Security: no hostPID: true in rendered output"
fi

# ── Test 15: No hostIPC ──────────────────────────────────────────────────────

if echo "${RENDERED}" | grep -qE 'hostIPC:\s*true'; then
    fail "Security: hostIPC: true found in rendered output"
else
    pass "Security: no hostIPC: true in rendered output"
fi

# ── Test 16: No privileged containers ────────────────────────────────────────

if echo "${RENDERED}" | grep -qE 'privileged:\s*true'; then
    fail "Security: privileged: true found in rendered output"
else
    pass "Security: no privileged: true containers in rendered output"
fi

# ── Test 17: Default-deny NetworkPolicy present ──────────────────────────────

if echo "${RENDERED}" | grep -q 'name: default-deny-all'; then
    pass "NetworkPolicy: default-deny-all NetworkPolicy present"
else
    fail "NetworkPolicy: default-deny-all NOT found in rendered output"
fi

# ── Test 18: Default-deny NP has both Ingress and Egress policyTypes ─────────

# Extract the default-deny-all block and check it has both policyTypes.
DENY_BLOCK="$(echo "${RENDERED}" | awk '/name: default-deny-all/{found=1} found{print} found && /^---/{if(NR>1) exit}')"
if echo "${DENY_BLOCK}" | grep -q 'Ingress' && echo "${DENY_BLOCK}" | grep -q 'Egress'; then
    pass "NetworkPolicy: default-deny-all has both Ingress and Egress policyTypes"
else
    fail "NetworkPolicy: default-deny-all missing Ingress or Egress policyTypes"
fi

# ── Test 19: PSS enforce=restricted namespace label ──────────────────────────

if echo "${RENDERED}" | grep -q 'pod-security.kubernetes.io/enforce: restricted'; then
    pass "PSS: pod-security.kubernetes.io/enforce: restricted label present on namespace"
else
    fail "PSS: pod-security.kubernetes.io/enforce: restricted label NOT found"
fi

# ── Test 20: Auth secret defaultMode is 0440 (decimal 288) ──────────────────

# The rendered YAML can show the int as 288 (decimal) or 0440 (octal notation
# depends on YAML serializer). Both represent the same value.
if echo "${RENDERED}" | grep -E 'defaultMode:\s*(288|0440)' | grep -v '#' | grep -q .; then
    pass "Secret: auth secret volume defaultMode is 0440 (288; no world access)"
else
    fail "Secret: auth secret volume defaultMode 0440/288 NOT found in rendered output"
fi

# ── Test 21: TLS off emits no cert-manager CRDs ──────────────────────────────

if echo "${RENDERED}" | grep -qE '^kind:\s*(Certificate|Issuer|ClusterIssuer)$'; then
    fail "TLS: cert-manager resources rendered when tls.enabled=false"
else
    pass "TLS: no cert-manager CRDs rendered when tls.enabled=false"
fi

# ── Test 22: TLS on emits Certificate and Issuer ────────────────────────────

if [[ -n "${RENDERED_TLS}" ]]; then
    TLS_HAS_CERT="$(echo "${RENDERED_TLS}" | grep -cE '^kind:\s*Certificate$' || true)"
    TLS_HAS_ISSUER="$(echo "${RENDERED_TLS}" | grep -cE '^kind:\s*Issuer$' || true)"
    if [[ "${TLS_HAS_CERT}" -ge 1 ]] && [[ "${TLS_HAS_ISSUER}" -ge 1 ]]; then
        pass "TLS: Certificate and Issuer rendered when tls.enabled=true + selfSigned=true"
    else
        fail "TLS: Certificate or Issuer missing when tls.enabled=true + selfSigned=true"
    fi
else
    skip_test "TLS: cert-manager render check skipped (template failed earlier)"
fi

# ── Test 23: Role (not ClusterRole) is present ──────────────────────────────

if echo "${RENDERED}" | grep -qE '^kind:\s*Role$'; then
    pass "RBAC: namespace-scoped Role present"
else
    fail "RBAC: namespace-scoped Role NOT found in rendered output"
fi

# ── Test 24: RoleBinding (not ClusterRoleBinding) is present ─────────────────

if echo "${RENDERED}" | grep -qE '^kind:\s*RoleBinding$'; then
    pass "RBAC: namespace-scoped RoleBinding present"
else
    fail "RBAC: namespace-scoped RoleBinding NOT found in rendered output"
fi

# ── Test 25: Namespace name follows runsecure-<scope> pattern ────────────────

if echo "${RENDERED}" | grep -qE 'name:\s*runsecure-'; then
    pass "Namespace: follows runsecure-<scope> naming convention"
else
    fail "Namespace: runsecure-<scope> pattern NOT found"
fi

# ── Test 26: Runtime image envs are immutable digest references ─────────────

for env_name in \
    RUNSECURE_PROXY_IMAGE \
    RUNSECURE_RUNNER_IMAGE_DEFAULT \
    RUNSECURE_RUNNER_IMAGE_NODE \
    RUNSECURE_RUNNER_IMAGE_PYTHON \
    RUNSECURE_RUNNER_IMAGE_RUST; do
    ENV_BLOCK="$(echo "${RENDERED}" | grep -A1 -- "- name: ${env_name}" || true)"
    if echo "${ENV_BLOCK}" | grep -Eq 'value: .*@sha256:[0-9a-f]{64}'; then
        pass "Kubernetes runtime: ${env_name} is immutable repository@sha256"
    else
        fail "Kubernetes runtime: ${env_name} immutable digest env missing"
    fi
done

# ── Test 27: Kubernetes deployment has no Docker dependency ────────────────

if echo "${RENDERED}" | grep -qE 'name:\s*DOCKER_HOST|socket-proxy:2375'; then
    fail "Kubernetes runtime: Docker/socket-proxy dependency found in orchestrator Deployment"
else
    pass "Kubernetes runtime: no DOCKER_HOST or socket-proxy endpoint injected"
fi

# ── Test 28: liveness and readiness use distinct truthful endpoints ────────

LIVENESS_BLOCK="$(echo "${RENDERED}" | sed -n '/^[[:space:]]*livenessProbe:/,/^[[:space:]]*readinessProbe:/p')"
READINESS_BLOCK="$(echo "${RENDERED}" | sed -n '/^[[:space:]]*readinessProbe:/,/^[[:space:]]*resources:/p')"
if echo "${LIVENESS_BLOCK}" | grep -q 'path: /healthz' &&
   ! echo "${LIVENESS_BLOCK}" | grep -q 'path: /readyz' &&
   echo "${READINESS_BLOCK}" | grep -q 'path: /readyz' &&
   ! echo "${READINESS_BLOCK}" | grep -q 'path: /healthz'; then
    pass "Liveness targets /healthz while readiness targets /readyz"
else
    fail "Liveness/readiness probes do not target distinct truthful endpoints"
fi

# ── Test 29: writable bounded egress state is under /tmp ───────────────────

if echo "${RENDERED}" | grep -A1 -- '- name: RUNSECURE_EGRESS_BASE_DIR' | grep -q '/tmp/runsecure/egress' &&
   echo "${RENDERED}" | grep -q 'sizeLimit: 256Mi'; then
    pass "Kubernetes runtime: egress state uses bounded writable memory volume"
else
    fail "Kubernetes runtime: writable bounded RUNSECURE_EGRESS_BASE_DIR missing"
fi

# ── Test 30: management Service exposes health and state listeners ──────────

if echo "${RENDERED}" | grep -q 'name: state' &&
   echo "${RENDERED}" | grep -q 'port: 8081'; then
    pass "Management Service exposes state listener 8081"
else
    fail "Management Service does not expose state listener 8081"
fi

# ── Test 31: singleton lifecycle contract is rendered ──────────────────────

if echo "${RENDERED}" | grep -q 'type: Recreate' &&
   echo "${RENDERED}" | grep -q 'terminationGracePeriodSeconds: 90' &&
   echo "${RENDERED}" | grep -q 'replicas: 1'; then
    pass "Kubernetes lifecycle: singleton Recreate deployment has 90s drain grace"
else
    fail "Kubernetes lifecycle: singleton/Recreate/90s drain contract missing"
fi

# ── Test 32: cluster dependency peers are rendered into env and policy ─────

NETWORK_ENV_OK=1
for env_name in RUNSECURE_KUBE_API_SERVER_PEERS RUNSECURE_KUBE_DNS_SERVICE_CIDRS \
  RUNSECURE_KUBE_DNS_NAMESPACE RUNSECURE_KUBE_DNS_POD_LABEL_KEY \
  RUNSECURE_KUBE_DNS_POD_LABEL_VALUE; do
    if ! echo "${RENDERED}" | grep -q -- "- name: ${env_name}"; then
        NETWORK_ENV_OK=0
    fi
done
if [[ "${NETWORK_ENV_OK}" -eq 1 ]] &&
   echo "${RENDERED}" | grep -q 'cidr: "10.96.0.1/32"' &&
   echo "${RENDERED}" | grep -q 'cidr: "10.96.0.10/32"' &&
   echo "${RENDERED}" | grep -q 'kubernetes.io/metadata.name: "kube-system"' &&
   echo "${RENDERED}" | grep -q '"k8s-app": "kube-dns"'; then
    pass "Kubernetes network: exact API pair and pre/post-DNAT DNS peers reach runtime and policy"
else
    fail "Kubernetes network: API/DNS runtime env or exact policy peer missing"
fi

# ── Test 33: unsafe replicas, drain grace, and broad CIDRs fail closed ─────

if render_chart --set replicaCount=2 &>/dev/null; then
    fail "Kubernetes lifecycle: replicaCount=2 was accepted"
else
    pass "Kubernetes lifecycle: replicaCount greater than one is rejected"
fi
if render_chart --set terminationGracePeriodSeconds=89 &>/dev/null; then
    fail "Kubernetes lifecycle: terminationGracePeriodSeconds=89 was accepted"
else
    pass "Kubernetes lifecycle: drain grace below 90 seconds is rejected"
fi
if render_chart --set kubernetesNetwork.dnsNamespace=KUBE_SYSTEM &>/dev/null; then
    fail "Kubernetes network: invalid DNS namespace was accepted"
else
    pass "Kubernetes network: DNS namespace selector must be valid"
fi
if render_chart --set 'kubernetesNetwork.dnsServiceCIDRs[0]=10.96.0.0/24' &>/dev/null ||
   render_chart --set 'kubernetesNetwork.dnsServiceCIDRs[1]=10.96.0.10/32' &>/dev/null; then
    fail "Kubernetes network: broad or duplicate DNS Service CIDR was accepted"
else
    pass "Kubernetes network: DNS Service peers must be unique exact /32s"
fi
if render_chart --set 'kubernetesNetwork.apiServerPeers[0].cidr=10.96.0.0/24' &>/dev/null; then
    fail "Kubernetes network: broad API-server CIDR was accepted"
else
    pass "Kubernetes network: API-server destination must be an exact /32"
fi
if render_chart --set 'kubernetesNetwork.apiServerPeers[0].port=0' &>/dev/null ||
   render_chart --set-string 'kubernetesNetwork.apiServerPeers[1].cidr=10.96.0.1/32' \
     --set 'kubernetesNetwork.apiServerPeers[1].port=443' &>/dev/null; then
    fail "Kubernetes network: invalid or duplicate API-server pair was accepted"
else
    pass "Kubernetes network: API-server pairs must be valid and unique"
fi

PAIR_RENDERED=$(render_chart \
  --set-string 'kubernetesNetwork.apiServerPeers[0].cidr=10.96.0.1/32' \
  --set 'kubernetesNetwork.apiServerPeers[0].port=443' \
  --set-string 'kubernetesNetwork.apiServerPeers[1].cidr=172.18.0.2/32' \
  --set 'kubernetesNetwork.apiServerPeers[1].port=6443' 2>/dev/null || echo "")
API_PAIR_POLICY=$(echo "${PAIR_RENDERED}" | sed -n '/# kube-apiserver Service and endpoints/,/# Cluster DNS/p')
SERVICE_PAIR_RULE=$(echo "${API_PAIR_POLICY}" | grep -B3 -A1 'cidr: "10.96.0.1/32"' || true)
ENDPOINT_PAIR_RULE=$(echo "${API_PAIR_POLICY}" | grep -B3 -A1 'cidr: "172.18.0.2/32"' || true)
if [[ $(echo "${API_PAIR_POLICY}" | grep -c '^    - ports:') -eq 2 ]] &&
   echo "${SERVICE_PAIR_RULE}" | grep -q 'port: 443' &&
   ! echo "${SERVICE_PAIR_RULE}" | grep -q 'port: 6443' &&
   echo "${ENDPOINT_PAIR_RULE}" | grep -q 'port: 6443' &&
   ! echo "${ENDPOINT_PAIR_RULE}" | grep -q 'port: 443'; then
    pass "Kubernetes network: API CIDRs and ports render as exact pairs without cross-pairs"
else
    fail "Kubernetes network: API peer rendering introduced a CIDR/port cross-product"
fi

# ── Print results ────────────────────────────────────────────────────────────

echo ""
echo "=== Helm Chart CIS/PSS Assertions ==="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [[ $FAIL -gt 0 ]]; then
    echo "FAILED: $PASS passed, $FAIL failed, $SKIP skipped"
    exit 1
else
    echo "PASSED: $PASS passed, $SKIP skipped"
    exit 0
fi
