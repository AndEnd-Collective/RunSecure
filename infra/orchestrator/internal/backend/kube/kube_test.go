package kube_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
)

// testInput returns a SpawnInput with stable, deterministic field values.
func testInput(spawnID string) backend.SpawnInput {
	return backend.SpawnInput{
		Scope:           "testscope",
		Repo:            "owner/repo",
		SpawnID:         spawnID,
		RunnerImage:     "ghcr.io/runsecure/runner-base:latest",
		ProxyImage:      "ghcr.io/runsecure/proxy:latest",
		JITConfigB64:    "dGVzdC1qaXQtY29uZmlnLWI2NA==",
		EgressConfigDir: "/tmp/egress",
		EnableDNSMasq:   false,
		TCPEgressPorts:  []int{443},
	}
}

// newBackend creates a kubeBackend backed by an in-memory fake clientset.
func newBackend(t *testing.T) (backend.Backend, *fake.Clientset) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	c := kube.NewClient(cs)
	return backendkube.New(c), cs
}

// ──────────────────────────────────────────────────────────────────────────────
// Name
// ──────────────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	b, _ := newBackend(t)
	assert.Equal(t, "kube", b.Name())
}

// ──────────────────────────────────────────────────────────────────────────────
// Spawn
// ──────────────────────────────────────────────────────────────────────────────

func TestSpawn_CreatesAllObjects(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()
	in := testInput("spawn-abc")

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope) // "runsecure-testscope"

	// ── Namespace ──────────────────────────────────────────────────────────
	_, err = cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	require.NoError(t, err, "namespace must be created by Spawn")

	// ── Default-deny NetworkPolicy (created by EnsureNamespace) ──────────
	_, err = cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny-all", metav1.GetOptions{})
	require.NoError(t, err, "default-deny-all policy must be created by EnsureNamespace via Spawn")

	// ── Secret ────────────────────────────────────────────────────────────
	secretName := h.Refs["secret"]
	require.NotEmpty(t, secretName, "Handle.Refs[secret] must be set")
	_, err = cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err, "Secret must be created by Spawn")

	// ── Service ──────────────────────────────────────────────────────────
	svcs, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, svcs.Items, 1, "exactly one Service must be created by Spawn")

	// ── NetworkPolicies (runner-egress + proxy-egress + proxy-ingress + default-deny) ─
	policies, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	// 4 total: default-deny-all + runner-egress + proxy-egress + proxy-ingress
	assert.Len(t, policies.Items, 4, "must have 4 NetworkPolicies after Spawn")

	// ── ProxyPod ──────────────────────────────────────────────────────────
	proxyPodName := h.Refs["proxy_pod"]
	require.NotEmpty(t, proxyPodName, "Handle.Refs[proxy_pod] must be set")
	_, err = cs.CoreV1().Pods(ns).Get(ctx, proxyPodName, metav1.GetOptions{})
	require.NoError(t, err, "proxy Pod must be created by Spawn")

	// ── RunnerPod ────────────────────────────────────────────────────────
	runnerPodName := h.Refs["runner_pod"]
	require.NotEmpty(t, runnerPodName, "Handle.Refs[runner_pod] must be set")
	runnerPod, err := cs.CoreV1().Pods(ns).Get(ctx, runnerPodName, metav1.GetOptions{})
	require.NoError(t, err, "runner Pod must be created by Spawn")

	// ── Handle fields ────────────────────────────────────────────────────
	assert.Equal(t, in.SpawnID, h.SpawnID)
	assert.Equal(t, "kube", h.Backend)
	assert.Equal(t, ns, h.Refs["namespace"])
	assert.Equal(t, "", h.Refs["network_name"])

	// ── Runner Pod security invariants ────────────────────────────────────
	// automountServiceAccountToken must be false.
	require.NotNil(t, runnerPod.Spec.AutomountServiceAccountToken)
	assert.False(t, *runnerPod.Spec.AutomountServiceAccountToken,
		"runner pod must have automountServiceAccountToken=false")

	// HTTP_PROXY / HTTPS_PROXY must point at the proxy Service DNS.
	svc := svcs.Items[0]
	expectedProxyDNS := fmt.Sprintf("%s.%s.svc", svc.Name, ns)
	expectedProxyURL := fmt.Sprintf("http://%s:3128", expectedProxyDNS)

	require.Len(t, runnerPod.Spec.Containers, 1, "runner pod must have exactly 1 container")
	runnerEnv := envMap(runnerPod.Spec.Containers[0].Env)
	assert.Equal(t, expectedProxyURL, runnerEnv["HTTP_PROXY"],
		"HTTP_PROXY must point at the proxy Service DNS")
	assert.Equal(t, expectedProxyURL, runnerEnv["HTTPS_PROXY"],
		"HTTPS_PROXY must point at the proxy Service DNS")
}

func TestSpawn_Handle_ContainsAllRequiredRefs(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()
	in := testInput("spawn-refs")

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	for _, key := range []string{"namespace", "secret", "runner_pod", "proxy_pod", "network_name"} {
		_, ok := h.Refs[key]
		assert.True(t, ok, "Handle.Refs must contain key %q", key)
	}
}

// TestSpawn_CreatesProxyIngressPolicy verifies that after a successful Spawn the
// fake cluster contains the ProxyIngress NetworkPolicy that allows the runner
// to reach the proxy on port 3128. This is the production bug fix: without this
// policy, the default-deny blocks proxy pod ingress under a real CNI (Calico).
func TestSpawn_CreatesProxyIngressPolicy(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()
	in := testInput("spawn-proxy-ingress")

	_, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope)
	expectedName := "rs-proxy-ingress-spawn-proxy-ingress"

	pol, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, expectedName, metav1.GetOptions{})
	require.NoError(t, err, "proxy-ingress NetworkPolicy must be created by Spawn")

	// Must target the proxy pod of this spawn.
	require.NotNil(t, pol.Spec.PodSelector.MatchLabels)
	assert.Equal(t, "proxy", pol.Spec.PodSelector.MatchLabels["runsecure.io/role"],
		"proxy-ingress podSelector must select role=proxy")
	assert.Equal(t, in.SpawnID, pol.Spec.PodSelector.MatchLabels["runsecure.io/spawn-id"],
		"proxy-ingress podSelector must pin this spawn-id")

	// Must have Ingress type only.
	require.Len(t, pol.Spec.PolicyTypes, 1, "proxy-ingress must declare exactly one policyType")
	assert.Equal(t, "Ingress", string(pol.Spec.PolicyTypes[0]),
		"proxy-ingress policyType must be Ingress")

	// Must have at least one ingress rule allowing the runner.
	require.NotEmpty(t, pol.Spec.Ingress, "proxy-ingress must have ingress rules")
	rule := pol.Spec.Ingress[0]
	require.NotEmpty(t, rule.From, "proxy-ingress rule must have From peers")
	peer := rule.From[0]
	require.NotNil(t, peer.PodSelector, "proxy-ingress From peer must have podSelector")
	assert.Equal(t, "runner", peer.PodSelector.MatchLabels["runsecure.io/role"],
		"proxy-ingress From must select role=runner")
	assert.Equal(t, in.SpawnID, peer.PodSelector.MatchLabels["runsecure.io/spawn-id"],
		"proxy-ingress From must pin the same spawn-id (cross-spawn isolation)")
}

// TestSpawn_Idempotent_Namespace verifies that calling Spawn on the same scope
// twice does not fail on the namespace already existing.
func TestSpawn_Idempotent_Namespace(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	_, err := b.Spawn(ctx, testInput("spawn-idem-1"))
	require.NoError(t, err, "first Spawn must succeed")

	_, err = b.Spawn(ctx, testInput("spawn-idem-2"))
	require.NoError(t, err, "second Spawn in the same scope must succeed (namespace already exists)")
}

// ──────────────────────────────────────────────────────────────────────────────
// WaitForExit
// ──────────────────────────────────────────────────────────────────────────────

func TestWaitForExit_Succeeded(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	in := testInput("spawn-wait-ok")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := h.Refs["namespace"]
	podName := h.Refs["runner_pod"]

	// In a goroutine, update runner pod status to Succeeded.
	go func() {
		time.Sleep(10 * time.Millisecond)
		pod, getErr := cs.CoreV1().Pods(ns).Get(context.Background(), podName, metav1.GetOptions{})
		if getErr != nil {
			return
		}
		updated := pod.DeepCopy()
		updated.Status.Phase = corev1.PodSucceeded
		_, _ = cs.CoreV1().Pods(ns).UpdateStatus(context.Background(), updated, metav1.UpdateOptions{})
	}()

	exitCode, timedOut := b.WaitForExit(ctx, h, 5*time.Second)
	assert.False(t, timedOut, "should not time out")
	assert.Equal(t, 0, exitCode, "Succeeded pod must yield exit code 0")
}

func TestWaitForExit_Failed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	in := testInput("spawn-wait-fail")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := h.Refs["namespace"]
	podName := h.Refs["runner_pod"]

	// In a goroutine, update runner pod status to Failed.
	go func() {
		time.Sleep(10 * time.Millisecond)
		pod, getErr := cs.CoreV1().Pods(ns).Get(context.Background(), podName, metav1.GetOptions{})
		if getErr != nil {
			return
		}
		updated := pod.DeepCopy()
		updated.Status.Phase = corev1.PodFailed
		_, _ = cs.CoreV1().Pods(ns).UpdateStatus(context.Background(), updated, metav1.UpdateOptions{})
	}()

	exitCode, timedOut := b.WaitForExit(ctx, h, 5*time.Second)
	assert.False(t, timedOut)
	assert.Equal(t, 1, exitCode, "Failed pod must yield exit code 1")
}

func TestWaitForExit_Timeout(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	in := testInput("spawn-wait-timeout")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	// Pod never transitions — use a very short timeout.
	exitCode, timedOut := b.WaitForExit(ctx, h, 50*time.Millisecond)
	assert.True(t, timedOut, "should time out when pod never transitions")
	assert.Equal(t, -1, exitCode, "timed-out wait must yield exit code -1")
}

// ──────────────────────────────────────────────────────────────────────────────
// Teardown
// ──────────────────────────────────────────────────────────────────────────────

func TestTeardown_DeletesOwningSecret(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()

	in := testInput("spawn-tear")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := h.Refs["namespace"]
	secretName := h.Refs["secret"]

	// Verify the Secret exists before teardown.
	_, err = cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err, "Secret must exist before Teardown")

	// Teardown (force flag is ignored by the kube backend).
	require.NoError(t, b.Teardown(ctx, h, false))

	// Secret must be gone.
	_, err = cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	assert.True(t, isNotFound(err), "Secret must be deleted after Teardown; got err: %v", err)
}

func TestTeardown_MissingSecret_ReturnsError(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	// Build a Handle pointing at a non-existent namespace/secret.
	h := backend.Handle{
		SpawnID: "ghost-spawn",
		Backend: "kube",
		Refs: map[string]string{
			"namespace":  "runsecure-ghost",
			"secret":     "rs-secret-ghost",
			"runner_pod": "rs-runner-ghost",
			"proxy_pod":  "rs-proxy-ghost",
		},
	}
	err := b.Teardown(ctx, h, true)
	require.Error(t, err, "Teardown on non-existent secret must return an error")
}

// ──────────────────────────────────────────────────────────────────────────────
// Reconcile
// ──────────────────────────────────────────────────────────────────────────────

func TestReconcile_FindsSpawnAfterSpawn(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()
	in := testInput("spawn-recon")

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	handles, err := b.Reconcile(ctx, in.Scope)
	require.NoError(t, err)
	require.Len(t, handles, 1, "Reconcile must return exactly one handle after one Spawn")

	found := handles[0]
	assert.Equal(t, in.SpawnID, found.SpawnID)
	assert.Equal(t, "kube", found.Backend)
	assert.Equal(t, h.Refs["namespace"], found.Refs["namespace"])
	assert.Equal(t, h.Refs["secret"], found.Refs["secret"])
	assert.Equal(t, h.Refs["runner_pod"], found.Refs["runner_pod"])
}

func TestReconcile_EmptyScope_ReturnsEmpty(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	handles, err := b.Reconcile(ctx, "never-used-scope")
	require.NoError(t, err)
	assert.Empty(t, handles, "Reconcile on an unused scope must return an empty slice")
}

func TestReconcile_MultipleSpawns(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()
	scope := "multi-scope"

	spawnIDs := []string{"recon-s1", "recon-s2", "recon-s3"}
	for _, id := range spawnIDs {
		in := testInput(id)
		in.Scope = scope
		_, err := b.Spawn(ctx, in)
		require.NoError(t, err, "Spawn %s must succeed", id)
	}

	handles, err := b.Reconcile(ctx, scope)
	require.NoError(t, err)
	assert.Len(t, handles, len(spawnIDs), "Reconcile must return one handle per spawn")

	byID := make(map[string]backend.Handle, len(handles))
	for _, h := range handles {
		byID[h.SpawnID] = h
	}
	for _, id := range spawnIDs {
		_, ok := byID[id]
		assert.True(t, ok, "spawn %s must appear in Reconcile result", id)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Spawn error paths
// ──────────────────────────────────────────────────────────────────────────────

// TestSpawn_ApplySpawnError verifies that when ApplySpawn fails, Spawn returns
// an error and attempts a best-effort cleanup (DeleteSpawn on the owning Secret).
func TestSpawn_ApplySpawnError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	// Inject a failure on the second secrets create call (the first create is
	// the Secret itself; ApplySpawn calls Create then Get). We fail on "pods"
	// create to simulate a partial failure after the Secret was created.
	injected := errors.New("injected pod create error")
	podCallCount := 0
	cs.PrependReactor("create", "pods", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		podCallCount++
		if podCallCount == 1 {
			return true, nil, injected
		}
		return false, nil, nil
	})

	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	in := testInput("spawn-applyerr")
	_, err := b.Spawn(ctx, in)
	require.Error(t, err, "Spawn must return an error when ApplySpawn fails")
	assert.Contains(t, err.Error(), "apply spawn")
}

// TestSpawn_EnsureNamespaceError verifies that an EnsureNamespace failure
// is propagated immediately (before any object creation).
func TestSpawn_EnsureNamespaceError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected namespace create error")
	cs.PrependReactor("create", "namespaces", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	_, err := b.Spawn(ctx, testInput("spawn-nserr"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ensure namespace")
}

// ──────────────────────────────────────────────────────────────────────────────
// WaitForExit — default (empty/unknown) phase
// ──────────────────────────────────────────────────────────────────────────────

// TestWaitForExit_UnknownPhase covers the default branch in WaitForExit.
// When WaitRunner returns a non-terminal phase (PodRunning) after the watch
// channel closes and relist is called, WaitForExit must return (1, false).
//
// We inject a Watch reactor that immediately stops the watcher, forcing
// WaitRunner into the relist path, which reads the pod in Running phase.
func TestWaitForExit_UnknownPhase(t *testing.T) {
	ns := "runsecure-unknown-phase"
	podName := "rs-runner-unknown"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	cs := fake.NewSimpleClientset(pod)

	// Override the Watch reactor so the channel is immediately closed, forcing
	// WaitRunner to fall through to relist (which reads the pod in Running phase).
	cs.PrependWatchReactor("pods", func(_ k8stesting.Action) (bool, watch.Interface, error) {
		fw := watch.NewRaceFreeFake()
		// Stop immediately so ResultChan closes.
		fw.Stop()
		return true, fw, nil
	})

	c := kube.NewClient(cs)
	b := backendkube.New(c)

	h := backend.Handle{
		SpawnID: "unknown-phase-spawn",
		Backend: "kube",
		Refs: map[string]string{
			"namespace":  ns,
			"runner_pod": podName,
		},
	}

	exitCode, timedOut := b.WaitForExit(context.Background(), h, 5*time.Second)
	// Running is not Succeeded or Failed → default branch → (1, false).
	assert.False(t, timedOut, "non-terminal phase from relist is not a timeout")
	assert.Equal(t, 1, exitCode, "non-Succeeded/non-Failed phase must map to exit code 1")
}

// TestReconcile_Error verifies that a ListSpawns error is propagated by Reconcile.
func TestReconcile_Error(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected list error")
	cs.PrependReactor("list", "pods", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	c := kube.NewClient(cs)
	b := backendkube.New(c)

	_, err := b.Reconcile(context.Background(), "err-scope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reconcile scope")
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

// envMap converts a slice of EnvVar into a name→value map.
func envMap(envs []corev1.EnvVar) map[string]string {
	m := make(map[string]string, len(envs))
	for _, e := range envs {
		m[e.Name] = e.Value
	}
	return m
}

// isNotFound returns true when err is a Kubernetes NotFound API error.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// k8s.io/apimachinery/pkg/api/errors.IsNotFound would work, but we keep
	// imports minimal — string match suffices for test assertions.
	return fmt.Sprintf("%v", err) != "" &&
		(containsStr(err.Error(), "not found") || containsStr(err.Error(), "NotFound"))
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
