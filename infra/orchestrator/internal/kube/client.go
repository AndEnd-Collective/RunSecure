// Package kube provides a thin wrapper around the Kubernetes client-go API for
// managing per-spawn runner+proxy stacks. It exposes only the operations
// required by the RunSecure orchestrator:
//   - EnsureNamespace: create the scoped namespace and default-deny policy.
//   - ApplySpawn: create all per-spawn objects with owner references.
//   - WaitRunner: watch a runner pod to a terminal phase.
//   - DeleteSpawn: cascade-delete a spawn via its owning Secret.
//   - ListSpawns: enumerate active spawns in a scope.
package kube

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// inClusterConfig and newForConfig are package-level variables so that
// export_test.go can swap them in unit tests to exercise every branch of
// NewInCluster without requiring a real Kubernetes cluster.
var inClusterConfig = rest.InClusterConfig

// newForConfig wraps kubernetes.NewForConfig with an interface return type so
// tests can inject a fake without a concrete *Clientset.
var newForConfig = func(cfg *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(cfg)
}

// Client wraps a kubernetes.Interface with the higher-level operations used by
// the orchestrator. It is intentionally thin — no caching, no informers — so
// unit tests can use fake.NewSimpleClientset() without any ceremony.
type Client struct {
	cs kubernetes.Interface
}

// SpawnObjects groups all Kubernetes objects that make up one per-spawn stack.
// The Secret is the owner; all others carry OwnerReferences to it so that
// deleting the Secret cascades to the entire spawn.
type SpawnObjects struct {
	Secret    *corev1.Secret
	Service   *corev1.Service
	Policies  []*networkingv1.NetworkPolicy
	ProxyPod  *corev1.Pod
	RunnerPod *corev1.Pod
}

// SpawnRef is a lightweight handle for a running spawn, suitable for returning
// in lists without pulling full object graphs.
type SpawnRef struct {
	SpawnID    string
	Namespace  string
	RunnerPod  string
	SecretName string
}

// NewClient constructs a Client from an existing kubernetes.Interface. Use this
// in tests (pass a fake) and in production code that already has a clientset.
func NewClient(cs kubernetes.Interface) *Client {
	return &Client{cs: cs}
}

// NewInCluster builds a Client using the in-cluster service-account credentials
// injected by Kubernetes. It is only usable when the orchestrator binary is
// running inside a pod.
func NewInCluster() (*Client, error) {
	cfg, err := inClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kube: in-cluster config: %w", err)
	}
	cs, err := newForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kube: new clientset: %w", err)
	}
	return NewClient(cs), nil
}

// EnsureNamespace creates the "runsecure-<scope>" namespace and the
// default-deny NetworkPolicy inside it. Both operations are idempotent:
// AlreadyExists errors are silently swallowed so callers may invoke this
// function on every reconcile without error.
func (c *Client) EnsureNamespace(ctx context.Context, scope string) error {
	ns := Namespace(scope)

	// Create the namespace; tolerate AlreadyExists.
	_, err := c.cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
			Labels: map[string]string{
				LabelScope: scope,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("kube: create namespace %q: %w", ns, err)
	}

	// Create the default-deny NetworkPolicy; tolerate AlreadyExists.
	policy := DefaultDenyNetworkPolicy(scope)
	_, err = c.cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, policy, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("kube: create default-deny policy in %q: %w", ns, err)
	}

	return nil
}

// ApplySpawn creates all objects for one spawn in the following order:
//  1. Secret (the owner).
//  2. Re-fetch the Secret to obtain its server-assigned UID.
//  3. Stamp OwnerReferences (via OwnerRef) on every other object.
//  4. Create Service, NetworkPolicies, ProxyPod, RunnerPod.
func (c *Client) ApplySpawn(ctx context.Context, objs SpawnObjects) error {
	ns := objs.Secret.Namespace

	// Step 1 — create the Secret (the owning object for GC cascade).
	created, err := c.cs.CoreV1().Secrets(ns).Create(ctx, objs.Secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("kube: create secret %q: %w", objs.Secret.Name, err)
	}

	// Step 2 — re-fetch to get the authoritative UID (the fake client populates
	// UID immediately, but a real API server may return a different object).
	secret, err := c.cs.CoreV1().Secrets(ns).Get(ctx, created.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("kube: get secret %q after create: %w", created.Name, err)
	}

	// Step 3 — build the OwnerReference from the live Secret.
	ownerRef := OwnerRef(secret)

	// Step 4 — stamp and create Service.
	objs.Service.OwnerReferences = []metav1.OwnerReference{ownerRef}
	if _, err := c.cs.CoreV1().Services(ns).Create(ctx, objs.Service, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("kube: create service %q: %w", objs.Service.Name, err)
	}

	// Stamp and create each NetworkPolicy.
	for _, p := range objs.Policies {
		p.OwnerReferences = []metav1.OwnerReference{ownerRef}
		if _, err := c.cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("kube: create network policy %q: %w", p.Name, err)
		}
	}

	// Stamp and create the proxy Pod.
	objs.ProxyPod.OwnerReferences = []metav1.OwnerReference{ownerRef}
	if _, err := c.cs.CoreV1().Pods(ns).Create(ctx, objs.ProxyPod, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("kube: create proxy pod %q: %w", objs.ProxyPod.Name, err)
	}

	// Stamp and create the runner Pod.
	objs.RunnerPod.OwnerReferences = []metav1.OwnerReference{ownerRef}
	if _, err := c.cs.CoreV1().Pods(ns).Create(ctx, objs.RunnerPod, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("kube: create runner pod %q: %w", objs.RunnerPod.Name, err)
	}

	return nil
}

// WaitRunner watches the named pod in ns until it reaches a terminal phase
// (Succeeded or Failed) or the timeout fires. It returns the pod's phase and
// whether the timeout was reached.
//
// If the watch channel closes before a terminal phase is observed (e.g. the
// API server restarted), WaitRunner re-lists the pod once to obtain its current
// phase, avoiding a spurious timeout.
func (c *Client) WaitRunner(ctx context.Context, ns, podName string, timeout time.Duration) (phase corev1.PodPhase, timedOut bool) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	watcher, err := c.cs.CoreV1().Pods(ns).Watch(timeoutCtx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + podName,
	})
	if err != nil {
		// Cannot establish a watch — fall through to the re-list path.
		return c.relist(ctx, ns, podName)
	}
	defer watcher.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				// Watch channel closed unexpectedly; re-list to get current phase.
				return c.relist(ctx, ns, podName)
			}
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			switch pod.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				return pod.Status.Phase, false
			}
		case <-timeoutCtx.Done():
			return "", true
		}
	}
}

// relist performs a one-shot Get to retrieve the pod's current phase. It is
// called when the watch channel closes unexpectedly. If the Get fails for any
// reason, an empty phase is returned (not a timeout).
func (c *Client) relist(ctx context.Context, ns, podName string) (corev1.PodPhase, bool) {
	pod, err := c.cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", false
	}
	return pod.Status.Phase, false
}

// DeleteSpawn deletes the owning Secret for a spawn. The Kubernetes garbage
// collector cascades the deletion to all objects that carry an OwnerReference
// pointing at that Secret (Service, NetworkPolicies, Pods).
func (c *Client) DeleteSpawn(ctx context.Context, ns, secretName string) error {
	if err := c.cs.CoreV1().Secrets(ns).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("kube: delete secret %q in %q: %w", secretName, ns, err)
	}
	return nil
}

// ListSpawns returns one SpawnRef per active runner pod in the given scope.
// It lists pods with the label selector "runsecure.io/scope=<scope>,
// runsecure.io/role=runner". The secret name is derived from the pod's
// OwnerReferences (Kind=="Secret"). If no OwnerReference is found, it falls
// back to the conventional name "rs-secret-<spawnID>".
func (c *Client) ListSpawns(ctx context.Context, scope string) ([]SpawnRef, error) {
	ns := Namespace(scope)
	selector := fmt.Sprintf("%s=%s,%s=%s", LabelScope, scope, LabelRole, RoleRunner)

	pods, err := c.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("kube: list runner pods in %q: %w", ns, err)
	}

	refs := make([]SpawnRef, 0, len(pods.Items))
	for _, pod := range pods.Items {
		spawnID := pod.Labels[LabelSpawnID]

		// Try to find the owning Secret name from OwnerReferences.
		secretName := ""
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "Secret" {
				secretName = ref.Name
				break
			}
		}
		if secretName == "" {
			secretName = spawnResourceName("secret", spawnID)
		}

		refs = append(refs, SpawnRef{
			SpawnID:    spawnID,
			Namespace:  ns,
			RunnerPod:  pod.Name,
			SecretName: secretName,
		})
	}

	return refs, nil
}
