package kube_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
func testInput(t *testing.T, spawnID string) backend.SpawnInput {
	t.Helper()
	egressDir := t.TempDir()
	for name, content := range map[string]string{
		"squid.conf": "# squid fixture", "haproxy.cfg": "# haproxy fixture",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(egressDir, name), []byte(content), 0o600))
	}
	return backend.SpawnInput{
		Scope:                "testscope",
		Repo:                 "owner/repo",
		SpawnID:              spawnID,
		RunnerImage:          "ghcr.io/runsecure/runner-base:latest",
		ProxyImage:           "ghcr.io/runsecure/proxy:latest",
		ResourcesMemory:      2 << 30,
		ResourcesNanoCPUs:    2_000_000_000,
		ResourcesPIDs:        512,
		JITConfigB64:         "dGVzdC1qaXQtY29uZmlnLWI2NA==",
		EgressConfigDir:      egressDir,
		EnableDNSMasq:        false,
		TCPEgressPorts:       []int{443},
		KubeDNSServiceCIDRs:  []string{"10.96.0.10/32"},
		KubeDNSNamespace:     "kube-system",
		KubeDNSPodLabelKey:   "k8s-app",
		KubeDNSPodLabelValue: "kube-dns",
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
	in := testInput(t, "spawn-abc")

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope) // "runsecure-testscope"

	// Helm owns Namespace creation. Runtime reconciliation must use only the
	// namespace-scoped API surface granted by the chart Role.
	for _, action := range cs.Actions() {
		assert.NotEqual(t, "namespaces", action.GetResource().Resource,
			"Spawn must not access the cluster-scoped Namespace API")
	}

	// ── Default-deny NetworkPolicy ─────────────────────────────────────────
	_, err = cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny-all", metav1.GetOptions{})
	require.NoError(t, err, "default-deny-all policy must be reconciled by Spawn")

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
	runner := runnerPod.Spec.Containers[0]
	runnerEnv := envMap(runner.Env)
	assert.Equal(t, expectedProxyURL, runnerEnv["HTTP_PROXY"],
		"HTTP_PROXY must point at the proxy Service DNS")
	assert.Equal(t, expectedProxyURL, runnerEnv["HTTPS_PROXY"],
		"HTTPS_PROXY must point at the proxy Service DNS")
	assert.Equal(t, int64(2_000), runner.Resources.Requests.Cpu().MilliValue())
	assert.Equal(t, int64(2_000), runner.Resources.Limits.Cpu().MilliValue())
	assert.Equal(t, int64(2<<30), runner.Resources.Requests.Memory().Value())
	assert.Equal(t, int64(2<<30), runner.Resources.Limits.Memory().Value())
	for _, volume := range runnerPod.Spec.Volumes {
		if volume.Name == "tmp" {
			require.NotNil(t, volume.EmptyDir)
			require.NotNil(t, volume.EmptyDir.SizeLimit)
			assert.Equal(t, int64(512<<20), volume.EmptyDir.SizeLimit.Value())
			return
		}
	}
	t.Fatal("runner Pod must have a bounded tmp volume")
}

func TestSpawn_Handle_ContainsAllRequiredRefs(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()
	in := testInput(t, "spawn-refs")

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
	in := testInput(t, "spawn-proxy-ingress")

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

// TestSpawn_Idempotent_DefaultDeny verifies that repeated reconciles tolerate
// the chart-owned default-deny policy already existing.
func TestSpawn_Idempotent_DefaultDeny(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	_, err := b.Spawn(ctx, testInput(t, "spawn-idem-1"))
	require.NoError(t, err, "first Spawn must succeed")

	_, err = b.Spawn(ctx, testInput(t, "spawn-idem-2"))
	require.NoError(t, err, "second Spawn in the same scope must tolerate the existing default-deny policy")
}

// ──────────────────────────────────────────────────────────────────────────────
// WaitForExit
// ──────────────────────────────────────────────────────────────────────────────

func TestWaitForExit_Succeeded(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	in := testInput(t, "spawn-wait-ok")
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

	in := testInput(t, "spawn-wait-fail")
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

	in := testInput(t, "spawn-wait-timeout")
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

	in := testInput(t, "spawn-tear")
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

func TestTeardown_MissingSecret_IsIdempotentSuccess(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	// Build a Handle pointing at a non-existent namespace/secret.
	h := backend.Handle{
		SpawnID: "ghost-spawn",
		Backend: "kube",
		Refs: map[string]string{
			"namespace":  "runsecure-ghost",
			"secret":     "rs-secret-ghost-spawn",
			"runner_pod": "rs-runner-ghost-spawn",
			"proxy_pod":  "rs-proxy-ghost-spawn",
			"repo_label": "owner_repo",
		},
	}
	require.NoError(t, b.Teardown(ctx, h, true),
		"Teardown on an already-absent owning Secret must succeed")
}

func TestTeardown_RemovesExactEgressConfigDir(t *testing.T) {
	b, _ := newBackend(t)
	egressDir := filepath.Join(t.TempDir(), "custom-egress", "spawn")
	require.NoError(t, os.MkdirAll(egressDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(egressDir, "squid.conf"), []byte("fixture"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(egressDir, "haproxy.cfg"), []byte("fixture"), 0o600))
	in := testInput(t, "spawn-egress-cleanup")
	in.EgressConfigDir = egressDir
	h, err := b.Spawn(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, egressDir, h.Refs["egress_config_dir"])

	require.NoError(t, b.Teardown(context.Background(), h, true))
	_, statErr := os.Stat(egressDir)
	require.True(t, os.IsNotExist(statErr))
}

// ──────────────────────────────────────────────────────────────────────────────
// Teardown error aggregation
// ──────────────────────────────────────────────────────────────────────────────

func TestTeardown_ReportsAllIndependentCleanupFailures(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "rs-secret-spawn-cleanup-errors", Namespace: "runsecure-cleanup-errors",
		Labels: map[string]string{
			"runsecure.io/scope": "cleanup-errors", "runsecure.io/repo": "owner_repo",
			"runsecure.io/spawn-id": "spawn-cleanup-errors", "runsecure.io/role": "proxy",
		},
	}}
	cs := fake.NewSimpleClientset(secret)
	deleteErr := errors.New("injected secret deletion failure")
	cs.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, deleteErr
	})
	b := backendkube.New(kube.NewClient(cs))

	// A child below a regular file makes RemoveAll fail with ENOTDIR without
	// relying on process permissions. Teardown must still attempt this cleanup
	// after the Kubernetes deletion fails, then preserve both causes.
	blockingParent := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blockingParent, []byte("fixture"), 0o600))
	h := backend.Handle{
		SpawnID: "spawn-cleanup-errors",
		Backend: "kube",
		Refs: map[string]string{
			"namespace":         "runsecure-cleanup-errors",
			"secret":            "rs-secret-spawn-cleanup-errors",
			"repo_label":        "owner_repo",
			"egress_config_dir": filepath.Join(blockingParent, "spawn"),
		},
	}

	err := b.Teardown(context.Background(), h, true)
	require.Error(t, err)
	require.ErrorIs(t, err, deleteErr)
	require.ErrorContains(t, err, "teardown spawn \"spawn-cleanup-errors\"")
	require.ErrorContains(t, err, "remove egress config")
}

// Reconcile

func TestReconcile_FindsSpawnAfterSpawn(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()
	in := testInput(t, "spawn-recon")

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
		in := testInput(t, id)
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

	in := testInput(t, "spawn-applyerr")
	_, err := b.Spawn(ctx, in)
	require.Error(t, err, "Spawn must return an error when ApplySpawn fails")
	assert.Contains(t, err.Error(), "apply spawn")
}

func TestSpawn_ApplyAndRollbackFailureReturnsExactTeardownHandle(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "pods", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("injected pod create error")
	})
	failDelete := true
	cs.PrependReactor("delete", "secrets", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		if failDelete {
			return true, nil, errors.New("injected secret delete error")
		}
		return false, nil, nil
	})
	b := backendkube.New(kube.NewClient(cs))
	in := testInput(t, "spawn-rollback-debt")

	h, err := b.Spawn(context.Background(), in)

	require.Error(t, err)
	require.Contains(t, err.Error(), "apply spawn")
	require.Contains(t, err.Error(), "rollback spawn")
	require.Equal(t, "kube", h.Backend)
	require.Equal(t, kube.Namespace(in.Scope), h.Refs["namespace"])
	require.NotEmpty(t, h.Refs["secret"])

	failDelete = false
	require.NoError(t, b.Teardown(context.Background(), h, true),
		"returned handle must support exact cleanup after the dependency recovers")
}

// TestSpawn_EnsureDefaultDenyError verifies that policy reconciliation failure
// is propagated immediately (before any object creation).
func TestSpawn_EnsureDefaultDenyError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected network policy create error")
	cs.PrependReactor("create", "networkpolicies", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	c := kube.NewClient(cs)
	b := backendkube.New(c)
	ctx := context.Background()

	_, err := b.Spawn(ctx, testInput(t, "spawn-nserr"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ensure default-deny policy")
}

func TestSpawn_RejectsUnboundedRunnerResourcesBeforeClusterMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*backend.SpawnInput)
		want   string
	}{
		{
			name:   "missing memory limit",
			mutate: func(in *backend.SpawnInput) { in.ResourcesMemory = 0 },
			want:   "runner memory limit must be positive",
		},
		{
			name:   "missing CPU limit",
			mutate: func(in *backend.SpawnInput) { in.ResourcesNanoCPUs = 0 },
			want:   "runner CPU limit must be positive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, cs := newBackend(t)
			in := testInput(t, "spawn-unbounded")
			tt.mutate(&in)

			_, err := b.Spawn(context.Background(), in)
			require.ErrorContains(t, err, tt.want)
			require.Empty(t, cs.Actions(), "invalid limits must fail before Kubernetes API access")
		})
	}
}

func TestSpawn_RejectsInvalidDNSSelectorBeforeClusterMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*backend.SpawnInput)
		want   string
	}{
		{
			name:   "empty service CIDRs",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSServiceCIDRs = nil },
			want:   "KubeDNSServiceCIDRs must not be empty",
		},
		{
			name:   "broad service CIDR",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSServiceCIDRs = []string{"10.96.0.0/24"} },
			want:   "KubeDNSServiceCIDRs must contain exact IPv4 /32 values",
		},
		{
			name: "duplicate service CIDR",
			mutate: func(in *backend.SpawnInput) {
				in.KubeDNSServiceCIDRs = []string{"10.96.0.10/32", "10.96.0.10/32"}
			},
			want: "KubeDNSServiceCIDRs must contain unique CIDRs",
		},
		{
			name:   "invalid namespace",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSNamespace = "INVALID_NAMESPACE" },
			want:   "KubeDNSNamespace must be a DNS-1123 label",
		},
		{
			name:   "invalid label key",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSPodLabelKey = "invalid key" },
			want:   "KubeDNSPodLabelKey must be a Kubernetes label key",
		},
		{
			name:   "empty label value",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSPodLabelValue = "" },
			want:   "KubeDNSPodLabelValue must not be empty",
		},
		{
			name:   "invalid label value",
			mutate: func(in *backend.SpawnInput) { in.KubeDNSPodLabelValue = "invalid value" },
			want:   "KubeDNSPodLabelValue must be a Kubernetes label value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, cs := newBackend(t)
			in := testInput(t, "spawn-invalid-dns")
			tt.mutate(&in)

			h, err := b.Spawn(context.Background(), in)

			require.ErrorContains(t, err, tt.want)
			require.Empty(t, h.SpawnID)
			namespaces, listErr := cs.CoreV1().Namespaces().List(
				context.Background(), metav1.ListOptions{},
			)
			require.NoError(t, listErr)
			require.Empty(t, namespaces.Items,
				"invalid DNS policy must fail before creating the scoped namespace")
		})
	}
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
// Spawn — egress config file injection
// ──────────────────────────────────────────────────────────────────────────────

func TestSpawn_SecretContainsSquidCfg(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()

	// Create a temp dir with a real squid.conf
	dir := t.TempDir()
	squidContent := "# squid config test"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "squid.conf"), []byte(squidContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "haproxy.cfg"), []byte("# haproxy"), 0o644))

	in := testInput(t, "spawn-squid-cfg")
	in.EgressConfigDir = dir

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope)
	secretName := h.Refs["secret"]
	secret, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, squidContent, secret.StringData["squid.conf"],
		"Secret must contain squid.conf content from EgressConfigDir")
}

func TestSpawn_SecretContainsHAProxyCfg(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()

	dir := t.TempDir()
	haproxyContent := "# haproxy config test"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "haproxy.cfg"), []byte(haproxyContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "squid.conf"), []byte("# squid"), 0o644))

	in := testInput(t, "spawn-haproxy-cfg")
	in.EgressConfigDir = dir

	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope)
	secretName := h.Refs["secret"]
	secret, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, haproxyContent, secret.StringData["haproxy.cfg"],
		"Secret must contain haproxy.cfg content from EgressConfigDir")
}

func TestSpawn_RequiredEgressConfigsFailClosed(t *testing.T) {
	b, _ := newBackend(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		setup  func(*testing.T, *backend.SpawnInput)
		wanted string
	}{
		{
			name: "missing directory",
			setup: func(_ *testing.T, in *backend.SpawnInput) {
				in.EgressConfigDir = ""
			},
			wanted: "directory is required",
		},
		{
			name: "empty squid",
			setup: func(t *testing.T, in *backend.SpawnInput) {
				require.NoError(t, os.WriteFile(filepath.Join(in.EgressConfigDir, "squid.conf"), nil, 0o600))
			},
			wanted: "squid.conf: config is empty",
		},
		{
			name: "missing haproxy",
			setup: func(t *testing.T, in *backend.SpawnInput) {
				require.NoError(t, os.Remove(filepath.Join(in.EgressConfigDir, "haproxy.cfg")))
			},
			wanted: "haproxy.cfg",
		},
		{
			name: "missing dnsmasq when enabled",
			setup: func(_ *testing.T, in *backend.SpawnInput) {
				in.EnableDNSMasq = true
			},
			wanted: "dnsmasq.conf",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(t, "spawn-missing-files")
			tc.setup(t, &in)
			_, err := b.Spawn(ctx, in)
			require.ErrorContains(t, err, tc.wanted)
		})
	}
}

func TestSpawn_SecretContainsDNSMasqCfgWhenEnabled(t *testing.T) {
	b, cs := newBackend(t)
	in := testInput(t, "spawn-dnsmasq-cfg")
	in.EnableDNSMasq = true
	content := "# dnsmasq fixture"
	require.NoError(t, os.WriteFile(
		filepath.Join(in.EgressConfigDir, "dnsmasq.conf"), []byte(content), 0o600,
	))

	h, err := b.Spawn(context.Background(), in)
	require.NoError(t, err)
	secret, err := cs.CoreV1().Secrets(kube.Namespace(in.Scope)).Get(
		context.Background(), h.Refs["secret"], metav1.GetOptions{},
	)
	require.NoError(t, err)
	require.Equal(t, content, secret.StringData["dnsmasq.conf"])
}

func TestSpawn_RunnerPodHasJITConfigFileEnv(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()

	in := testInput(t, "spawn-jit-env")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope)
	runnerPodName := h.Refs["runner_pod"]
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, runnerPodName, metav1.GetOptions{})
	require.NoError(t, err)

	require.Len(t, pod.Spec.Containers, 1)
	runnerEnv := envMap(pod.Spec.Containers[0].Env)
	assert.Equal(t, "/var/run/runsecure/jit-config", runnerEnv["RUNNER_JIT_CONFIG_FILE"],
		"runner pod must have RUNNER_JIT_CONFIG_FILE set")
}

func TestSpawn_RunnerPodMountsJITSecret(t *testing.T) {
	b, cs := newBackend(t)
	ctx := context.Background()

	in := testInput(t, "spawn-jit-mount")
	h, err := b.Spawn(ctx, in)
	require.NoError(t, err)

	ns := kube.Namespace(in.Scope)
	secretName := h.Refs["secret"]
	runnerPodName := h.Refs["runner_pod"]
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, runnerPodName, metav1.GetOptions{})
	require.NoError(t, err)

	// Find the secret volume
	var secretVol *corev1.SecretVolumeSource
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil && v.Secret.SecretName == secretName {
			secretVol = v.Secret
			break
		}
	}
	require.NotNil(t, secretVol, "runner pod must have a volume sourced from the per-spawn secret")
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
