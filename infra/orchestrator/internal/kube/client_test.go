package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────────────────────────────────────
// EnsureNamespace
// ──────────────────────────────────────────────────────────────────────────────

func TestEnsureNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClient(cs)
	ctx := context.Background()
	scope := "test-scope"
	ns := Namespace(scope)

	// First call — both objects must be created.
	require.NoError(t, c.EnsureNamespace(ctx, scope))

	_, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	require.NoError(t, err, "namespace must exist after EnsureNamespace")

	_, err = cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny-all", metav1.GetOptions{})
	require.NoError(t, err, "default-deny-all policy must exist after EnsureNamespace")

	// Second call — must be idempotent (no error on AlreadyExists).
	require.NoError(t, c.EnsureNamespace(ctx, scope), "EnsureNamespace must be idempotent")
}

// ──────────────────────────────────────────────────────────────────────────────
// ApplySpawn
// ──────────────────────────────────────────────────────────────────────────────

func TestApplySpawn(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClient(cs)
	ctx := context.Background()

	ns := "runsecure-test"
	secretName := "rs-secret-abc123"

	objs := SpawnObjects{
		Secret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ns,
			},
		},
		Service: &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rs-proxy-svc-abc123",
				Namespace: ns,
			},
		},
		Policies: []*networkingv1.NetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rs-runner-egress-abc123",
					Namespace: ns,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rs-proxy-egress-abc123",
					Namespace: ns,
				},
			},
		},
		ProxyPod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rs-proxy-abc123",
				Namespace: ns,
			},
		},
		RunnerPod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rs-runner-abc123",
				Namespace: ns,
			},
		},
	}

	// Pre-create the namespace so objects can be placed there.
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	require.NoError(t, c.ApplySpawn(ctx, objs))

	// Assert Secret exists.
	secret, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err, "Secret must exist after ApplySpawn")

	// Assert Service exists and has OwnerReference to the Secret.
	svc, err := cs.CoreV1().Services(ns).Get(ctx, "rs-proxy-svc-abc123", metav1.GetOptions{})
	require.NoError(t, err)
	assertOwnerRef(t, svc.OwnerReferences, secret.Name)

	// Assert both NetworkPolicies exist and have OwnerReferences.
	for _, pName := range []string{"rs-runner-egress-abc123", "rs-proxy-egress-abc123"} {
		p, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, pName, metav1.GetOptions{})
		require.NoError(t, err, "policy %s must exist", pName)
		assertOwnerRef(t, p.OwnerReferences, secret.Name)
	}

	// Assert ProxyPod exists and has OwnerReference.
	proxyPod, err := cs.CoreV1().Pods(ns).Get(ctx, "rs-proxy-abc123", metav1.GetOptions{})
	require.NoError(t, err)
	assertOwnerRef(t, proxyPod.OwnerReferences, secret.Name)

	// Assert RunnerPod exists and has OwnerReference.
	runnerPod, err := cs.CoreV1().Pods(ns).Get(ctx, "rs-runner-abc123", metav1.GetOptions{})
	require.NoError(t, err)
	assertOwnerRef(t, runnerPod.OwnerReferences, secret.Name)
}

// assertOwnerRef verifies that refs contains exactly one entry with Kind=="Secret"
// and the given name.
func assertOwnerRef(t *testing.T, refs []metav1.OwnerReference, secretName string) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == "Secret" && r.Name == secretName {
			return
		}
	}
	t.Errorf("expected OwnerReference{Kind:Secret, Name:%q}, got %+v", secretName, refs)
}

// ──────────────────────────────────────────────────────────────────────────────
// WaitRunner
// ──────────────────────────────────────────────────────────────────────────────

func TestWaitRunner_Succeeded(t *testing.T) {
	ns := "runsecure-wait-test"
	podName := "rs-runner-wait1"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
		},
	}

	// Pre-seed the fake clientset with the pod so Watch can observe it.
	cs := fake.NewSimpleClientset(pod)
	c := NewClient(cs)
	ctx := context.Background()

	// In a goroutine, update the pod status to Succeeded after a short delay.
	go func() {
		time.Sleep(10 * time.Millisecond)
		updated := pod.DeepCopy()
		updated.Status.Phase = corev1.PodSucceeded
		_, _ = cs.CoreV1().Pods(ns).UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	}()

	phase, timedOut := c.WaitRunner(ctx, ns, podName, 5*time.Second)
	assert.False(t, timedOut, "should not time out")
	assert.Equal(t, corev1.PodSucceeded, phase)
}

func TestWaitRunner_Timeout(t *testing.T) {
	ns := "runsecure-wait-test"
	podName := "rs-runner-wait2"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
		},
	}

	cs := fake.NewSimpleClientset(pod)
	c := NewClient(cs)
	ctx := context.Background()

	// Use a very short timeout — pod never transitions.
	phase, timedOut := c.WaitRunner(ctx, ns, podName, 50*time.Millisecond)
	assert.True(t, timedOut, "should time out")
	assert.Equal(t, corev1.PodPhase(""), phase)
}

func TestWaitRunner_WatchChannelClosed(t *testing.T) {
	// Exercise the relist path directly: when the watch channel closes, WaitRunner
	// calls relist which does a single Get to return the current pod phase.
	ns := "runsecure-relist-test"
	podName := "rs-runner-relist"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
		},
	}

	cs := fake.NewSimpleClientset(pod)
	c := NewClient(cs)
	ctx := context.Background()

	// Call relist directly to verify it returns the current pod phase.
	phase, timedOut := c.relist(ctx, ns, podName)
	assert.Equal(t, corev1.PodFailed, phase, "relist should return the current pod phase")
	assert.False(t, timedOut, "relist never returns timedOut=true")
}

func TestWaitRunner_RelistMissingPod(t *testing.T) {
	// Exercise the relist error path: if the pod no longer exists, relist
	// returns an empty phase and false (not timed out).
	ns := "runsecure-missing-test"
	podName := "rs-runner-missing"

	cs := fake.NewSimpleClientset()
	c := NewClient(cs)
	ctx := context.Background()

	phase, timedOut := c.relist(ctx, ns, podName)
	assert.Equal(t, corev1.PodPhase(""), phase, "missing pod should return empty phase")
	assert.False(t, timedOut)
}

// ──────────────────────────────────────────────────────────────────────────────
// DeleteSpawn
// ──────────────────────────────────────────────────────────────────────────────

func TestDeleteSpawn(t *testing.T) {
	ns := "runsecure-del-test"
	secretName := "rs-secret-del1"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
		},
	}

	cs := fake.NewSimpleClientset(secret)
	c := NewClient(cs)
	ctx := context.Background()

	require.NoError(t, c.DeleteSpawn(ctx, ns, secretName))

	_, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	require.True(t, k8serrors.IsNotFound(err), "Secret must be deleted; got error: %v", err)
}

// ──────────────────────────────────────────────────────────────────────────────
// ListSpawns
// ──────────────────────────────────────────────────────────────────────────────

func TestListSpawns(t *testing.T) {
	scope := "myscope"
	ns := Namespace(scope)
	secretUID := types.UID("fake-uid-1")

	// Two runner pods with an OwnerReference to a Secret.
	runnerPod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs-runner-spawn1",
			Namespace: ns,
			Labels: map[string]string{
				LabelScope:   scope,
				LabelRole:    RoleRunner,
				LabelSpawnID: "spawn1",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Secret",
					Name:       "rs-secret-spawn1",
					UID:        secretUID,
				},
			},
		},
	}

	runnerPod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs-runner-spawn2",
			Namespace: ns,
			Labels: map[string]string{
				LabelScope:   scope,
				LabelRole:    RoleRunner,
				LabelSpawnID: "spawn2",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Secret",
					Name:       "rs-secret-spawn2",
					UID:        secretUID,
				},
			},
		},
	}

	// One proxy pod in the same namespace — must NOT appear in the list.
	proxyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs-proxy-spawn1",
			Namespace: ns,
			Labels: map[string]string{
				LabelScope:   scope,
				LabelRole:    RoleProxy,
				LabelSpawnID: "spawn1",
			},
		},
	}

	cs := fake.NewSimpleClientset(runnerPod1, runnerPod2, proxyPod)
	c := NewClient(cs)
	ctx := context.Background()

	refs, err := c.ListSpawns(ctx, scope)
	require.NoError(t, err)
	require.Len(t, refs, 2, "ListSpawns must return exactly 2 runner pods")

	// Build a map for order-independent assertions.
	byID := make(map[string]SpawnRef, len(refs))
	for _, r := range refs {
		byID[r.SpawnID] = r
	}

	ref1, ok := byID["spawn1"]
	require.True(t, ok, "spawn1 must be in the list")
	assert.Equal(t, "rs-runner-spawn1", ref1.RunnerPod)
	assert.Equal(t, ns, ref1.Namespace)
	assert.Equal(t, "rs-secret-spawn1", ref1.SecretName)

	ref2, ok := byID["spawn2"]
	require.True(t, ok, "spawn2 must be in the list")
	assert.Equal(t, "rs-runner-spawn2", ref2.RunnerPod)
	assert.Equal(t, "rs-secret-spawn2", ref2.SecretName)
}

// ──────────────────────────────────────────────────────────────────────────────
// Error-path tests (for coverage of branches that return errors)
// ──────────────────────────────────────────────────────────────────────────────

// TestEnsureNamespace_NSCreateError verifies that a non-AlreadyExists error from
// namespace creation is propagated.
func TestEnsureNamespace_NSCreateError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected ns create error")
	cs.PrependReactor("create", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	err := c.EnsureNamespace(context.Background(), "err-scope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create namespace")
}

// TestEnsureNamespace_PolicyCreateError verifies that a non-AlreadyExists error
// from NetworkPolicy creation is propagated.
func TestEnsureNamespace_PolicyCreateError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected policy create error")
	cs.PrependReactor("create", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	err := c.EnsureNamespace(context.Background(), "err-scope2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create default-deny policy")
}

// TestApplySpawn_SecretCreateError verifies that a Secret creation error is
// propagated by ApplySpawn.
func TestApplySpawn_SecretCreateError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected secret create error")
	cs.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	objs := SpawnObjects{
		Secret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-err", Namespace: "runsecure-errns"},
		},
		Service:   &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "runsecure-errns"}},
		Policies:  []*networkingv1.NetworkPolicy{},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: "runsecure-errns"}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: "runsecure-errns"}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create secret")
}

// TestApplySpawn_ServiceCreateError verifies that a Service creation error is
// propagated by ApplySpawn.
func TestApplySpawn_ServiceCreateError(t *testing.T) {
	ns := "runsecure-svcerr"
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected svc create error")
	cs.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	objs := SpawnObjects{
		Secret:    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-svcerr", Namespace: ns}},
		Service:   &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: ns}},
		Policies:  []*networkingv1.NetworkPolicy{},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: ns}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: ns}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create service")
}

// TestApplySpawn_PolicyCreateError verifies that a NetworkPolicy creation error
// is propagated.
func TestApplySpawn_PolicyCreateError(t *testing.T) {
	ns := "runsecure-polerr"
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected policy create error")
	cs.PrependReactor("create", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	objs := SpawnObjects{
		Secret:  &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-polerr", Namespace: ns}},
		Service: &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: ns}},
		Policies: []*networkingv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Name: "policy1", Namespace: ns}},
		},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: ns}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: ns}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create network policy")
}

// TestApplySpawn_ProxyPodCreateError verifies that a proxy pod creation error
// is propagated.
func TestApplySpawn_ProxyPodCreateError(t *testing.T) {
	ns := "runsecure-proxypoderr"
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected proxy pod create error")
	podCallCount := 0
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		podCallCount++
		if podCallCount == 1 {
			// Fail on first pod create (proxy pod).
			return true, nil, injected
		}
		return false, nil, nil
	})
	c := NewClient(cs)
	objs := SpawnObjects{
		Secret:    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-pperr", Namespace: ns}},
		Service:   &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: ns}},
		Policies:  []*networkingv1.NetworkPolicy{},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: ns}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: ns}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create proxy pod")
}

// TestApplySpawn_RunnerPodCreateError verifies that a runner pod creation error
// is propagated.
func TestApplySpawn_RunnerPodCreateError(t *testing.T) {
	ns := "runsecure-runnerpoderr"
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected runner pod create error")
	podCallCount := 0
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		podCallCount++
		if podCallCount == 2 {
			// Fail on second pod create (runner pod).
			return true, nil, injected
		}
		return false, nil, nil
	})
	c := NewClient(cs)
	objs := SpawnObjects{
		Secret:    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-rperr", Namespace: ns}},
		Service:   &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: ns}},
		Policies:  []*networkingv1.NetworkPolicy{},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: ns}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: ns}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create runner pod")
}

// TestDeleteSpawn_Error verifies that a delete error is propagated.
func TestDeleteSpawn_Error(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected delete error")
	cs.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	err := c.DeleteSpawn(context.Background(), "runsecure-del-err", "rs-secret-del-err")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete secret")
}

// TestListSpawns_Error verifies that a list error is propagated.
func TestListSpawns_Error(t *testing.T) {
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected list error")
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})
	c := NewClient(cs)
	_, err := c.ListSpawns(context.Background(), "err-scope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list runner pods")
}

// TestListSpawns_FallbackSecretName exercises the path where a pod has no
// OwnerReference with Kind=="Secret" and the name is derived conventionally.
func TestListSpawns_FallbackSecretName(t *testing.T) {
	scope := "fallback-scope"
	ns := Namespace(scope)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs-runner-fb1",
			Namespace: ns,
			Labels: map[string]string{
				LabelScope:   scope,
				LabelRole:    RoleRunner,
				LabelSpawnID: "fb1",
			},
			// No OwnerReferences — fallback name derivation must kick in.
		},
	}

	cs := fake.NewSimpleClientset(pod)
	c := NewClient(cs)
	ctx := context.Background()

	refs, err := c.ListSpawns(ctx, scope)
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "rs-secret-fb1", refs[0].SecretName, "fallback secret name must be rs-secret-<spawnID>")
}

// ──────────────────────────────────────────────────────────────────────────────
// NewInCluster — injectable-var branches
// ──────────────────────────────────────────────────────────────────────────────

// TestNewInCluster_InClusterConfigError covers the branch where rest.InClusterConfig
// returns an error (e.g. not running inside a pod).
func TestNewInCluster_InClusterConfigError(t *testing.T) {
	injected := errors.New("not in cluster")

	orig := *InClusterConfig
	*InClusterConfig = func() (*rest.Config, error) { return nil, injected }
	defer func() { *InClusterConfig = orig }()

	_, err := NewInCluster()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "in-cluster config")
}

// TestNewInCluster_NewForConfigError covers the branch where kubernetes.NewForConfig
// returns an error after a successful InClusterConfig call.
func TestNewInCluster_NewForConfigError(t *testing.T) {
	injected := errors.New("bad config")

	origCfg := *InClusterConfig
	*InClusterConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { *InClusterConfig = origCfg }()

	origNew := *NewForConfig
	*NewForConfig = func(cfg *rest.Config) (kubernetes.Interface, error) { return nil, injected }
	defer func() { *NewForConfig = origNew }()

	_, err := NewInCluster()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "new clientset")
}

// TestNewInCluster_Success covers the happy path: both injected functions
// succeed and NewInCluster returns a non-nil *Client.
func TestNewInCluster_Success(t *testing.T) {
	origCfg := *InClusterConfig
	*InClusterConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	defer func() { *InClusterConfig = origCfg }()

	fakeCS := fake.NewSimpleClientset()
	origNew := *NewForConfig
	*NewForConfig = func(cfg *rest.Config) (kubernetes.Interface, error) { return fakeCS, nil }
	defer func() { *NewForConfig = origNew }()

	c, err := NewInCluster()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// TestNewForConfigWrapper exercises the default newForConfig wrapper body
// (the anonymous function assigned at package initialisation time). Passing a
// non-nil *rest.Config is enough — the call may succeed or fail depending on
// the environment; either outcome covers the statement.
func TestNewForConfigWrapper(t *testing.T) {
	// Retrieve the current (default) function value before any test replaces it.
	// This directly exercises the `return kubernetes.NewForConfig(cfg)` statement.
	fn := *NewForConfig
	// Use a minimal valid config; NewForConfig with an empty Host returns an
	// error but still traverses the function body.
	_, _ = fn(&rest.Config{Host: "http://127.0.0.1:1"})
}

// ──────────────────────────────────────────────────────────────────────────────
// ApplySpawn — Get-after-Create error path
// ──────────────────────────────────────────────────────────────────────────────

// TestApplySpawn_GetSecretAfterCreateError verifies that when the re-fetch of
// the Secret after creation fails, ApplySpawn propagates the error.
func TestApplySpawn_GetSecretAfterCreateError(t *testing.T) {
	ns := "runsecure-geterr"
	cs := fake.NewSimpleClientset()
	injected := errors.New("injected get error")

	// Allow the create to succeed but fail on get.
	cs.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	c := NewClient(cs)
	objs := SpawnObjects{
		Secret:    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rs-secret-geterr", Namespace: ns}},
		Service:   &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: ns}},
		Policies:  []*networkingv1.NetworkPolicy{},
		ProxyPod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "proxy", Namespace: ns}},
		RunnerPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: ns}},
	}
	err := c.ApplySpawn(context.Background(), objs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get secret")
}

// ──────────────────────────────────────────────────────────────────────────────
// WaitRunner — additional branch coverage
// ──────────────────────────────────────────────────────────────────────────────

// TestWaitRunner_WatchError covers the branch where Watch() itself returns an
// error. WaitRunner must fall through to relist() and return the pod's current
// phase.
func TestWaitRunner_WatchError(t *testing.T) {
	ns := "runsecure-watcherr"
	podName := "rs-runner-watcherr"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	cs := fake.NewSimpleClientset(pod)
	injected := errors.New("watch unavailable")
	cs.PrependWatchReactor("pods", func(action k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, injected
	})

	c := NewClient(cs)
	phase, timedOut := c.WaitRunner(context.Background(), ns, podName, 5*time.Second)
	assert.False(t, timedOut, "relist path must not report timeout")
	// relist reads the pod's phase from the fake store.
	assert.Equal(t, corev1.PodSucceeded, phase)
}

// TestWaitRunner_WatchChannelClosedViaFakeWatch covers the branch where the
// watch channel closes unexpectedly mid-stream. WaitRunner must call relist()
// and return the pod's current phase.
func TestWaitRunner_WatchChannelClosedViaFakeWatch(t *testing.T) {
	ns := "runsecure-closed"
	podName := "rs-runner-closed"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	}

	cs := fake.NewSimpleClientset(pod)

	// Inject a RaceFreeFakeWatcher whose channel we close immediately.
	fw := watch.NewRaceFreeFake()
	cs.PrependWatchReactor("pods", func(action k8stesting.Action) (bool, watch.Interface, error) {
		return true, fw, nil
	})

	// Close the channel before WaitRunner has a chance to consume any events.
	fw.Stop()

	c := NewClient(cs)
	phase, timedOut := c.WaitRunner(context.Background(), ns, podName, 5*time.Second)
	assert.False(t, timedOut, "closed channel must not report timeout")
	assert.Equal(t, corev1.PodFailed, phase, "relist must return current pod phase after channel close")
}

// TestWaitRunner_NonPodEventIgnored covers the branch where a watch event
// carries a non-Pod object (event.Object is not *corev1.Pod). WaitRunner must
// skip that event and keep waiting until a terminal phase is observed.
func TestWaitRunner_NonPodEventIgnored(t *testing.T) {
	ns := "runsecure-nonpod"
	podName := "rs-runner-nonpod"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	cs := fake.NewSimpleClientset(pod)

	fw := watch.NewRaceFreeFake()
	cs.PrependWatchReactor("pods", func(action k8stesting.Action) (bool, watch.Interface, error) {
		return true, fw, nil
	})

	// Emit a non-Pod event (a ConfigMap) first, then a real terminal Pod event.
	go func() {
		time.Sleep(5 * time.Millisecond)
		// Non-Pod object — type assertion will fail inside WaitRunner; event skipped.
		fw.Action(watch.Modified, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "not-a-pod", Namespace: ns},
		})
		time.Sleep(5 * time.Millisecond)
		// Now emit the terminal pod event.
		updated := pod.DeepCopy()
		updated.Status.Phase = corev1.PodSucceeded
		fw.Modify(updated)
	}()

	c := NewClient(cs)
	phase, timedOut := c.WaitRunner(context.Background(), ns, podName, 5*time.Second)
	assert.False(t, timedOut)
	assert.Equal(t, corev1.PodSucceeded, phase)
}
