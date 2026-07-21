// Package kube provides a thin wrapper around the Kubernetes client-go API for
// managing per-spawn runner+proxy stacks. It exposes only the operations
// required by the RunSecure orchestrator:
//   - EnsureDefaultDenyPolicy: reconcile the namespace default-deny policy.
//   - ApplySpawn: create all per-spawn objects with owner references.
//   - WaitRunner: watch a runner pod to a terminal phase.
//   - DeleteSpawn: cascade-delete a spawn via its owning Secret.
//   - ListSpawns: enumerate active spawns in a scope.
package kube

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	RepoLabel  string
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

// EnsureDefaultDenyPolicy creates the default-deny NetworkPolicy in the
// chart-provisioned "runsecure-<scope>" namespace. It deliberately performs no
// cluster-scoped Namespace API call: the orchestrator's Helm Role is scoped to
// this namespace and must not require namespace-create privileges.
//
// AlreadyExists is tolerated so callers may invoke this on every reconcile.
func (c *Client) EnsureDefaultDenyPolicy(ctx context.Context, scope string) error {
	ns := Namespace(scope)

	// Create the default-deny NetworkPolicy; tolerate AlreadyExists.
	policy := DefaultDenyNetworkPolicy(scope)
	_, err := c.cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, policy, metav1.CreateOptions{})
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

	// Establish the watch from an observed resourceVersion. Without this Get,
	// a short-lived runner can reach a terminal phase before the watch starts;
	// Kubernetes versions that do not send initial watch events would then leave
	// us waiting until the wall timeout even though the job already finished.
	pod, err := c.cs.CoreV1().Pods(ns).Get(timeoutCtx, podName, metav1.GetOptions{})
	if err != nil {
		return "", waitDeadlineExpired(ctx, timeoutCtx)
	}
	if isTerminalPodPhase(pod.Status.Phase) {
		return pod.Status.Phase, false
	}

	watcher, err := c.cs.CoreV1().Pods(ns).Watch(timeoutCtx, metav1.ListOptions{
		FieldSelector:   "metadata.name=" + podName,
		ResourceVersion: pod.ResourceVersion,
	})
	if err != nil {
		// Cannot establish a watch — fall through to the re-list path.
		phase, timedOut := c.relist(timeoutCtx, ns, podName)
		if phase == "" && waitDeadlineExpired(ctx, timeoutCtx) {
			return "", true
		}
		return phase, timedOut
	}
	defer watcher.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				// Watch channel closed unexpectedly; re-list to get current phase.
				phase, timedOut := c.relist(timeoutCtx, ns, podName)
				if phase == "" && waitDeadlineExpired(ctx, timeoutCtx) {
					return "", true
				}
				return phase, timedOut
			}
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			if isTerminalPodPhase(pod.Status.Phase) {
				return pod.Status.Phase, false
			}
		case <-timeoutCtx.Done():
			// A parent cancellation is not a runner wall timeout.
			return "", ctx.Err() == nil
		}
	}
}

func waitDeadlineExpired(parent, bounded context.Context) bool {
	return parent.Err() == nil && bounded.Err() == context.DeadlineExceeded
}

func isTerminalPodPhase(phase corev1.PodPhase) bool {
	return phase == corev1.PodSucceeded || phase == corev1.PodFailed
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

// DeleteSpawn removes every per-spawn object carrying the exact scope and
// spawn-id labels, then confirms that no such object remains. Explicitly
// deleting dependants is required for ownerless partial spawns: a missing
// Secret cannot be treated as successful cleanup while a Pod, Service, or
// NetworkPolicy still consumes capacity or retains network access.
//
// Resource names and roles must also match RunSecure's deterministic object
// contract. A label-spoofed or ambiguously-owned object therefore fails closed
// instead of being swept up by a broad selector delete.
func (c *Client) DeleteSpawn(
	ctx context.Context,
	ns, secretName, spawnID, repoLabel string,
) error {
	scope, err := validateSpawnIdentity(ns, secretName, spawnID, repoLabel)
	if err != nil {
		return err
	}
	resources, err := c.listExactSpawnResources(ctx, ns, scope, spawnID, repoLabel)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if err := c.deleteSpawnResource(ctx, ns, resource); err != nil {
			return err
		}
	}
	return c.waitForSpawnDeleted(ctx, ns, scope, spawnID, repoLabel)
}

type spawnResource struct {
	kind string
	name string
}

func validateSpawnIdentity(ns, secretName, spawnID, repoLabel string) (string, error) {
	scope, ok := strings.CutPrefix(ns, "runsecure-")
	if !ok || scope == "" || Namespace(scope) != ns {
		return "", fmt.Errorf("kube: invalid spawn namespace %q", ns)
	}
	if spawnID == "" {
		return "", fmt.Errorf("kube: empty spawn ID for namespace %q", ns)
	}
	if repoLabel == "" {
		return "", fmt.Errorf("kube: empty repository label for spawn %q", spawnID)
	}
	expectedSecret := spawnResourceName("secret", spawnID)
	if secretName != expectedSecret {
		return "", fmt.Errorf(
			"kube: secret %q does not match spawn %q (want %q)",
			secretName,
			spawnID,
			expectedSecret,
		)
	}
	return scope, nil
}

func (c *Client) listExactSpawnResources(
	ctx context.Context,
	ns, scope, spawnID, repoLabel string,
) ([]spawnResource, error) {
	selector := labels.Set{
		LabelScope:   scope,
		LabelSpawnID: spawnID,
	}.AsSelector().String()
	resources := make([]spawnResource, 0, 7)

	pods, err := c.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn pods in %q: %w", ns, err)
	}
	for i := range pods.Items {
		resources, err = appendSpawnResource(resources, "pod", &pods.Items[i], spawnID, repoLabel)
		if err != nil {
			return nil, err
		}
	}

	services, err := c.cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn services in %q: %w", ns, err)
	}
	for i := range services.Items {
		resources, err = appendSpawnResource(resources, "service", &services.Items[i], spawnID, repoLabel)
		if err != nil {
			return nil, err
		}
	}

	policies, err := c.cs.NetworkingV1().NetworkPolicies(ns).List(
		ctx,
		metav1.ListOptions{LabelSelector: selector},
	)
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn network policies in %q: %w", ns, err)
	}
	for i := range policies.Items {
		resources, err = appendSpawnResource(
			resources, "networkpolicy", &policies.Items[i], spawnID, repoLabel,
		)
		if err != nil {
			return nil, err
		}
	}

	secrets, err := c.cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn secrets in %q: %w", ns, err)
	}
	for i := range secrets.Items {
		resources, err = appendSpawnResource(resources, "secret", &secrets.Items[i], spawnID, repoLabel)
		if err != nil {
			return nil, err
		}
	}

	return resources, nil
}

func appendSpawnResource(
	resources []spawnResource,
	kind string,
	object metav1.Object,
	spawnID string,
	repoLabel string,
) ([]spawnResource, error) {
	expectedRole, ok := expectedSpawnResourceRole(kind, object.GetName(), spawnID)
	if !ok || object.GetLabels()[LabelRole] != expectedRole {
		return nil, fmt.Errorf(
			"kube: unexpected %s %q for spawn %q",
			kind,
			object.GetName(),
			spawnID,
		)
	}
	actualRepoLabel := object.GetLabels()[LabelRepo]
	if actualRepoLabel == "" || (repoLabel != "" && actualRepoLabel != repoLabel) {
		return nil, fmt.Errorf(
			"kube: %s %q has repository label %q, want %q",
			kind,
			object.GetName(),
			actualRepoLabel,
			repoLabel,
		)
	}
	expectedSecret := spawnResourceName("secret", spawnID)
	for _, owner := range object.GetOwnerReferences() {
		if owner.Kind != "Secret" || owner.Name != expectedSecret {
			return nil, fmt.Errorf(
				"kube: %s %q has unexpected owner %s %q",
				kind,
				object.GetName(),
				owner.Kind,
				owner.Name,
			)
		}
	}
	return append(resources, spawnResource{kind: kind, name: object.GetName()}), nil
}

func expectedSpawnResourceRole(kind, name, spawnID string) (string, bool) {
	expected := map[string]string{
		"pod/" + spawnResourceName("runner", spawnID):                  RoleRunner,
		"pod/" + spawnResourceName("proxy", spawnID):                   RoleProxy,
		"service/" + spawnResourceName("proxy-svc", spawnID):           RoleProxy,
		"networkpolicy/" + spawnResourceName("runner-egress", spawnID): RoleRunner,
		"networkpolicy/" + spawnResourceName("proxy-egress", spawnID):  RoleProxy,
		"networkpolicy/" + spawnResourceName("proxy-ingress", spawnID): RoleProxy,
		"secret/" + spawnResourceName("secret", spawnID):               RoleProxy,
	}
	role, ok := expected[kind+"/"+name]
	return role, ok
}

func (c *Client) deleteSpawnResource(ctx context.Context, ns string, resource spawnResource) error {
	background := metav1.DeletePropagationBackground
	zero := int64(0)
	options := metav1.DeleteOptions{PropagationPolicy: &background}
	var err error
	switch resource.kind {
	case "pod":
		options.GracePeriodSeconds = &zero
		err = c.cs.CoreV1().Pods(ns).Delete(ctx, resource.name, options)
	case "service":
		err = c.cs.CoreV1().Services(ns).Delete(ctx, resource.name, options)
	case "networkpolicy":
		err = c.cs.NetworkingV1().NetworkPolicies(ns).Delete(ctx, resource.name, options)
	case "secret":
		foreground := metav1.DeletePropagationForeground
		options.PropagationPolicy = &foreground
		err = c.cs.CoreV1().Secrets(ns).Delete(ctx, resource.name, options)
	default:
		return fmt.Errorf("kube: unsupported spawn resource kind %q", resource.kind)
	}
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf(
			"kube: delete spawn %s %q in %q: %w",
			resource.kind,
			resource.name,
			ns,
			err,
		)
	}
	return nil
}

func (c *Client) waitForSpawnDeleted(
	ctx context.Context,
	ns, scope, spawnID, repoLabel string,
) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		resources, err := c.listExactSpawnResources(ctx, ns, scope, spawnID, repoLabel)
		switch {
		case err != nil:
			return fmt.Errorf("kube: confirm spawn %q deletion in %q: %w", spawnID, ns, err)
		case len(resources) == 0:
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("kube: confirm spawn %q deletion in %q: %w", spawnID, ns, ctx.Err())
		case <-ticker.C:
		}
	}
}

// ListSpawns returns one SpawnRef per active or partially-created spawn in the
// given scope. Every per-spawn resource kind is inspected so a partially
// created Service, NetworkPolicy, proxy Pod, or runner Pod remains recoverable
// even when its owning Secret is absent. Conflicting or non-deterministically
// named objects fail closed instead of allowing reconciliation to delete an
// ambiguous resource set.
func (c *Client) ListSpawns(ctx context.Context, scope string) ([]SpawnRef, error) {
	ns := Namespace(scope)
	selector := labels.Set{LabelScope: scope}.AsSelector().String() + "," + LabelSpawnID
	secrets, err := c.cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn secrets in %q: %w", ns, err)
	}

	refsByID := make(map[string]SpawnRef, len(secrets.Items))
	for i := range secrets.Items {
		if err := mergeDiscoveredSpawn(refsByID, ns, "secret", &secrets.Items[i]); err != nil {
			return nil, err
		}
	}

	pods, err := c.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn pods in %q: %w", ns, err)
	}
	for i := range pods.Items {
		if err := mergeDiscoveredSpawn(refsByID, ns, "pod", &pods.Items[i]); err != nil {
			return nil, err
		}
	}

	services, err := c.cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn services in %q: %w", ns, err)
	}
	for i := range services.Items {
		if err := mergeDiscoveredSpawn(refsByID, ns, "service", &services.Items[i]); err != nil {
			return nil, err
		}
	}

	policies, err := c.cs.NetworkingV1().NetworkPolicies(ns).List(
		ctx,
		metav1.ListOptions{LabelSelector: selector},
	)
	if err != nil {
		return nil, fmt.Errorf("kube: list spawn network policies in %q: %w", ns, err)
	}
	for i := range policies.Items {
		if err := mergeDiscoveredSpawn(refsByID, ns, "networkpolicy", &policies.Items[i]); err != nil {
			return nil, err
		}
	}

	refs := make([]SpawnRef, 0, len(refsByID))
	for _, ref := range refsByID {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].SpawnID < refs[j].SpawnID
	})
	return refs, nil
}

func mergeDiscoveredSpawn(
	refsByID map[string]SpawnRef,
	ns, kind string,
	object metav1.Object,
) error {
	spawnID := object.GetLabels()[LabelSpawnID]
	if spawnID == "" {
		return fmt.Errorf("kube: spawn %s %q in %q has empty %s", kind, object.GetName(), ns, LabelSpawnID)
	}
	if _, err := appendSpawnResource(nil, kind, object, spawnID, ""); err != nil {
		return err
	}
	expectedSecret := spawnResourceName("secret", spawnID)
	repoLabel := object.GetLabels()[LabelRepo]
	if existing, exists := refsByID[spawnID]; exists {
		if existing.SecretName != expectedSecret ||
			existing.RunnerPod != spawnResourceName("runner", spawnID) ||
			existing.RepoLabel != repoLabel {
			return fmt.Errorf("kube: conflicting resources for spawn ID %q", spawnID)
		}
		return nil
	}
	refsByID[spawnID] = SpawnRef{
		SpawnID:    spawnID,
		Namespace:  ns,
		RunnerPod:  spawnResourceName("runner", spawnID),
		SecretName: expectedSecret,
		RepoLabel:  repoLabel,
	}
	return nil
}
