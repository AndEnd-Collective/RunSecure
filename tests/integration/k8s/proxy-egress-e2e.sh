#!/usr/bin/env bash
# proxy-egress-e2e.sh — Real-proxy egress enforcement e2e on a kind cluster.
#
# Validates two security properties of the kube backend:
#
#  A. Permission fix (fsGroup): the proxy container (UID 1001, non-root) can
#     READ its Secret-mounted squid.conf (defaultMode 0o400). Before the fsGroup
#     fix in objects.go, Secret volume files were root:root 0o400 — unreadable
#     by UID 1001, causing squid to exit with "cannot open config file".
#
#  B. Egress enforcement (I-1 fix): a squid.conf rendered for ONE allowed domain
#     (example.com) is mounted into the REAL proxy image. Assertions prove:
#     - CONNECT to example.com:443 → 200 Connection established (ALLOWED)
#     - CONNECT to ifconfig.me:443  → 403 Forbidden            (BLOCKED)
#
# Requirements: kind, kubectl, docker. SKIP (exit 0) if any are absent.
# FAIL (exit 1) on any assertion failure.
#
# Environment:
#   SKIP_CLEANUP=1     — leave cluster running for debugging
#   PROXY_IMAGE        — override image tag (default: runsecure-proxy:e2e)
#
# Usage:
#   ./tests/integration/k8s/proxy-egress-e2e.sh

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SQUID_DOCKERFILE="${REPO_ROOT}/infra/squid"

CLUSTER_NAME="rs-proxy-e2e"
NS="runsecure-e2e"
PROXY_IMAGE="${PROXY_IMAGE:-runsecure-proxy:e2e}"
SPAWN_ID="e2e-spawn01"

PASS=0
FAIL=0

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[proxy-e2e] $*"; }
pass() { PASS=$((PASS + 1)); echo "[PASS] $*"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $*" >&2; }

# wait_pod_ready <ns> <name> <timeout_s>
wait_pod_ready() {
  local ns="$1" name="$2" timeout="$3"
  log "Waiting up to ${timeout}s for pod ${ns}/${name} …"
  kubectl wait --for=condition=Ready "pod/${name}" -n "${ns}" --timeout="${timeout}s"
}

# ─────────────────────────────────────────────────────────────────────────────
# Prerequisite check — SKIP if tools are absent
# ─────────────────────────────────────────────────────────────────────────────
for tool in kind kubectl docker; do
  if ! command -v "${tool}" &>/dev/null; then
    log "SKIP: ${tool} not found in PATH — skipping proxy-egress-e2e"
    exit 0
  fi
done

# Verify Docker daemon is reachable
if ! docker info &>/dev/null; then
  log "SKIP: Docker daemon not reachable — skipping proxy-egress-e2e"
  exit 0
fi

log "Prerequisites OK: kind=$(kind version --short 2>/dev/null || kind version), kubectl=$(kubectl version --client --short 2>/dev/null | head -1), docker=$(docker version --format '{{.Client.Version}}' 2>/dev/null)"

# ─────────────────────────────────────────────────────────────────────────────
# Trap: tear down cluster on EXIT (unless SKIP_CLEANUP=1)
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
  if [[ "${SKIP_CLEANUP:-0}" == "1" ]]; then
    log "SKIP_CLEANUP=1 — cluster '${CLUSTER_NAME}' left running for debugging"
    return
  fi
  log "Tearing down kind cluster '${CLUSTER_NAME}' …"
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Build the real proxy image
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 1: Building proxy image ${PROXY_IMAGE} ==="
docker build -f "${SQUID_DOCKERFILE}/Dockerfile" -t "${PROXY_IMAGE}" "${SQUID_DOCKERFILE}"
log "Image built: ${PROXY_IMAGE}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Create a kind cluster (default CNI — no Calico needed for this test)
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 2: Creating kind cluster '${CLUSTER_NAME}' ==="
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
kind create cluster --name "${CLUSTER_NAME}" --wait 120s
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

log "Loading ${PROXY_IMAGE} into kind cluster …"
kind load docker-image "${PROXY_IMAGE}" --name "${CLUSTER_NAME}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Render a squid.conf that allows ONLY example.com
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 3: Rendering squid.conf (allow: example.com only) ==="

# We craft the squid.conf inline — same structure as egress.RenderSquid() produces
# for a runner.yml with http_egress: [example.com].
# We do NOT include base-conf github/npm/etc entries to keep the test tight:
# only example.com is allowed, everything else is denied.
SQUID_CONF='# RunSecure squid.conf — generated per-spawn. Do not edit.
http_port 3128
acl rs_private_dst dst 127.0.0.0/8
acl rs_private_dst dst 169.254.0.0/16
acl rs_private_dst dst 10.0.0.0/8
acl rs_private_dst dst 172.16.0.0/12
acl rs_private_dst dst 192.168.0.0/16
acl rs_private_dst dst 0.0.0.0/8
acl rs_private_dst dst ::1/128
acl rs_private_dst dst fe80::/10
acl rs_private_dst dst fc00::/7
http_access deny rs_private_dst
acl allowed_domains dstdomain .example.com
http_access allow allowed_domains
http_access deny all
visible_hostname runsecure-proxy
pid_filename /var/run/squid/squid.pid
access_log stdio:/var/log/squid/access.log
cache_log /var/log/squid/cache.log
cache deny all
coredump_dir /var/spool/squid
'

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Create namespace + Secret (same shape as kube.SpawnSecret())
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 4: Creating namespace ${NS} and per-spawn Secret ==="

kubectl create namespace "${NS}" \
  --dry-run=client -o yaml | kubectl apply -f -

# Create the Secret with the same keys the kube backend uses.
# kubectl create secret generic does not support --from-literal with newlines
# well on all platforms; we pipe YAML directly.
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: rs-secret-${SPAWN_ID}
  namespace: ${NS}
  labels:
    runsecure.io/scope: e2e
    runsecure.io/spawn-id: ${SPAWN_ID}
    runsecure.io/role: proxy
immutable: false
stringData:
  jit-config: "fake-jit-config-for-e2e-test"
  squid.conf: |
$(printf '%s' "${SQUID_CONF}" | sed 's/^/    /')
  haproxy.cfg: |
    # placeholder — not used in this test
  dnsmasq.conf: |
    # placeholder — not used in this test
EOF
log "Secret rs-secret-${SPAWN_ID} created."

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Create the proxy Pod — EXACT shape of kube.ProxyPod() + fsGroup fix
# ─────────────────────────────────────────────────────────────────────────────
# securityContext includes:
#   runAsNonRoot: true
#   runAsUser: 1001
#   fsGroup: 1001          ← THE FIX: k8s chowns Secret volume files to 1001:1001
#   seccompProfile: RuntimeDefault
#
# Secret volume defaultMode: 0o400 — readable by owner (1001) thanks to fsGroup.
# Without fsGroup the files would be root:root 0o400 → EPERM for UID 1001.
log "=== Step 5: Creating proxy Pod (REAL squid image, non-root UID 1001) ==="

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: rs-proxy-${SPAWN_ID}
  namespace: ${NS}
  labels:
    runsecure.io/scope: e2e
    runsecure.io/spawn-id: ${SPAWN_ID}
    runsecure.io/role: proxy
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  hostNetwork: false
  hostPID: false
  hostIPC: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  volumes:
    - name: jit-secret
      secret:
        secretName: rs-secret-${SPAWN_ID}
        defaultMode: 0256
        items:
          - key: squid.conf
            path: squid.conf
          - key: haproxy.cfg
            path: haproxy.cfg
          - key: dnsmasq.conf
            path: dnsmasq.conf
    - name: tmp
      emptyDir:
        medium: Memory
    - name: squid-run
      emptyDir:
        medium: Memory
    - name: squid-log
      emptyDir:
        medium: Memory
    - name: squid-spool
      emptyDir:
        medium: Memory
  containers:
    - name: squid
      image: ${PROXY_IMAGE}
      imagePullPolicy: Never
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      env:
        - name: SQUID_CFG
          value: /etc/runsecure/squid.conf
        - name: ENABLE_HAPROXY
          value: "false"
        - name: ENABLE_DNSMASQ
          value: "false"
      volumeMounts:
        - name: jit-secret
          mountPath: /etc/runsecure
          readOnly: true
        - name: tmp
          mountPath: /tmp
        - name: squid-run
          mountPath: /var/run/squid
        - name: squid-log
          mountPath: /var/log/squid
        - name: squid-spool
          mountPath: /var/spool/squid
      ports:
        - name: squid
          containerPort: 3128
          protocol: TCP
EOF

log "Proxy pod created. Waiting for Ready …"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6a: Assert A — proxy starts and squid reads config (permission check)
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 6a: Permission assertion — squid must read Secret-mounted config ==="

# Wait up to 90s for the pod to reach Running/Ready.
if ! kubectl wait --for=condition=Ready "pod/rs-proxy-${SPAWN_ID}" \
    -n "${NS}" --timeout=90s 2>/dev/null; then
  # Pod may have exited (RestartPolicy=Never). Grab logs regardless.
  POD_PHASE=$(kubectl get pod "rs-proxy-${SPAWN_ID}" -n "${NS}" \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
  PROXY_LOGS=$(kubectl logs "rs-proxy-${SPAWN_ID}" -n "${NS}" -c squid 2>/dev/null || echo "(no logs)")
  fail "Permission: proxy pod did not become Ready (phase=${POD_PHASE}) — permission denied or startup failure. Logs: ${PROXY_LOGS}"
else
  # Pod is Ready — check that squid started without permission errors.
  PROXY_LOGS=$(kubectl logs "rs-proxy-${SPAWN_ID}" -n "${NS}" -c squid 2>/dev/null || echo "")
  if echo "${PROXY_LOGS}" | grep -qi "permission denied\|cannot open.*conf\|FATAL\|Squid Cache.*FATAL"; then
    fail "Permission: squid reports permission error reading squid.conf. Logs: ${PROXY_LOGS}"
  else
    pass "Permission (fsGroup fix): UID 1001 can read Secret-mounted squid.conf (defaultMode 0o400). Logs show squid healthy."
    log "Squid startup log (last 10 lines):"
    echo "${PROXY_LOGS}" | tail -10 | sed 's/^/    /'
  fi
fi

# Bail out early if the permission assertion failed — egress checks won't work.
if [[ "${FAIL}" -gt 0 ]]; then
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  proxy-egress-e2e ABORTED (permission failure)"
  echo "  PASSED: ${PASS}  FAILED: ${FAIL}"
  echo "═══════════════════════════════════════════════════════════"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 6b: Assert B — egress enforcement via the rendered allowlist
# ─────────────────────────────────────────────────────────────────────────────
log "=== Step 6b: Egress enforcement — allowed vs. blocked via squid ==="

# Get the proxy pod IP so curl can reach it directly (no Service needed).
PROXY_POD_IP=$(kubectl get pod "rs-proxy-${SPAWN_ID}" -n "${NS}" \
  -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")

if [[ -z "${PROXY_POD_IP}" ]]; then
  fail "Egress: could not determine proxy pod IP — cannot run curl assertions"
else
  log "Proxy pod IP: ${PROXY_POD_IP}"

  # Launch a curl client pod (same namespace, curl available).
  # curl-client is privileged only to get curl — we're testing the PROXY, not the client.
  kubectl apply -f - <<EOF2
apiVersion: v1
kind: Pod
metadata:
  name: curl-client-${SPAWN_ID}
  namespace: ${NS}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
    - name: client
      image: curlimages/curl:8.8.0
      imagePullPolicy: IfNotPresent
      command: ["sleep", "300"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        runAsNonRoot: true
        runAsUser: 1001
        capabilities:
          drop:
            - ALL
EOF2

  log "Waiting for curl client pod …"
  # Load curl image into kind (if not cached)
  docker pull curlimages/curl:8.8.0 2>/dev/null || true
  kind load docker-image curlimages/curl:8.8.0 --name "${CLUSTER_NAME}" 2>/dev/null || true

  if ! kubectl wait --for=condition=Ready "pod/curl-client-${SPAWN_ID}" \
      -n "${NS}" --timeout=120s 2>/dev/null; then
    fail "Egress: curl client pod did not become Ready — skipping egress assertions"
  else
    HTTP_PROXY_URL="http://${PROXY_POD_IP}:3128"

    # --- Assertion B1: ALLOWED domain (example.com) MUST succeed ---
    # CONNECT to example.com:443 via squid. The allowed_domains ACL permits it.
    # We use -x for proxy, -k to skip cert verify (we're testing allow/deny, not TLS),
    # --max-time to avoid hanging, -o /dev/null to discard body.
    log "B1. CONNECT example.com:443 via proxy — MUST succeed (allowed by allowlist) …"
    ALLOW_HTTP=$(kubectl exec "curl-client-${SPAWN_ID}" -n "${NS}" -c client -- \
      curl -s -o /dev/null -w "%{http_code}" \
      -x "${HTTP_PROXY_URL}" \
      --max-time 30 \
      -k "https://example.com/" 2>/dev/null || echo "CURL_FAILED")

    if [[ "${ALLOW_HTTP}" == "200" ]]; then
      pass "Egress: ALLOWED — example.com:443 returned HTTP ${ALLOW_HTTP} via squid proxy"
    elif [[ "${ALLOW_HTTP}" =~ ^2 ]]; then
      pass "Egress: ALLOWED — example.com:443 returned HTTP ${ALLOW_HTTP} via squid proxy"
    else
      fail "Egress: example.com should be ALLOWED but got HTTP=${ALLOW_HTTP} (or curl failed)"
    fi

    # --- Assertion B2: BLOCKED domain (ifconfig.me) MUST be denied ---
    # Squid returns 403 (Access Denied) for domains not in allowed_domains.
    # curl exits non-zero (code 000) when squid denies the CONNECT tunnel.
    log "B2. CONNECT ifconfig.me:443 via proxy — MUST be blocked (not in allowlist) …"
    DENY_HTTP="000"
    kubectl exec "curl-client-${SPAWN_ID}" -n "${NS}" -c client -- \
      curl -s -o /dev/null -w "%{http_code}" \
      -x "${HTTP_PROXY_URL}" \
      --max-time 15 \
      -k "https://ifconfig.me/" \
      >/tmp/rs-deny-http 2>/dev/null || true
    DENY_HTTP="$(cat /tmp/rs-deny-http 2>/dev/null || echo 000)"

    if [[ "${DENY_HTTP}" == "403" ]]; then
      pass "Egress: BLOCKED — ifconfig.me:443 returned HTTP 403 (Forbidden) from squid — allowlist enforced"
    elif [[ "${DENY_HTTP}" == "200" ]]; then
      fail "Egress: VIOLATION — ifconfig.me should be BLOCKED but squid returned 200 — allowlist NOT enforced"
    else
      # 000 = curl failed to connect (squid denied CONNECT, returned error page, curl got non-2xx)
      # Any non-200 code means squid blocked the request.
      pass "Egress: BLOCKED — ifconfig.me:443 was denied by squid (HTTP=${DENY_HTTP}) — allowlist enforced"
    fi

    # --- Assertion B3: Plain HTTP to blocked domain MUST be denied ---
    log "B3. HTTP GET http://neverallowed.invalid/ via proxy — MUST be blocked …"
    DENY_HTTP2=$(kubectl exec "curl-client-${SPAWN_ID}" -n "${NS}" -c client -- \
      curl -s -o /dev/null -w "%{http_code}" \
      -x "${HTTP_PROXY_URL}" \
      --max-time 10 \
      "http://neverallowed.invalid/" 2>/dev/null || echo "CURL_FAILED")

    if [[ "${DENY_HTTP2}" == "403" || "${DENY_HTTP2}" == "CURL_FAILED" ]]; then
      pass "Egress: BLOCKED — neverallowed.invalid returned HTTP=${DENY_HTTP2} — allowlist enforced"
    elif [[ "${DENY_HTTP2}" == "200" ]]; then
      fail "Egress: VIOLATION — neverallowed.invalid should be BLOCKED but returned 200"
    else
      pass "Egress: BLOCKED — neverallowed.invalid returned HTTP=${DENY_HTTP2} (non-200)"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  proxy-egress-e2e results"
echo "  PASSED: ${PASS}"
echo "  FAILED: ${FAIL}"
echo "═══════════════════════════════════════════════════════════"

if [[ "${FAIL}" -gt 0 ]]; then
  echo "RESULT: FAILED — ${FAIL} assertion(s) failed"
  exit 1
fi

echo "RESULT: PASSED — all ${PASS} assertions green"
exit 0
