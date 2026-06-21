// Package kube implements backend.Backend using Kubernetes: each spawn is
// realised as a runner Pod + proxy Pod + ClusterIP Service + per-spawn
// NetworkPolicies + a per-spawn Secret (the GC owner) inside a per-scope
// namespace.  The kube.Client wrapper handles all API calls; the kube object
// builders produce the typed k8s objects from a backend.SpawnInput.
package kube

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
)

// kubeBackend implements backend.Backend over a kube.Client.
type kubeBackend struct {
	c *kube.Client
}

// New returns a backend.Backend that manages runner stacks in Kubernetes.
func New(c *kube.Client) backend.Backend {
	return &kubeBackend{c: c}
}

// Name returns the backend identifier.
func (b *kubeBackend) Name() string { return "kube" }

// Spawn creates a full per-spawn stack in Kubernetes:
//  1. Ensures the scoped namespace and its default-deny NetworkPolicy exist.
//  2. Builds all objects (Secret, Service, NetworkPolicies, ProxyPod,
//     RunnerPod) via the kube object builders.
//  3. Creates all objects via ApplySpawn (owner references are stamped there).
//
// On any error after EnsureNamespace, a best-effort DeleteSpawn is attempted
// to clean up partially created objects before the error is returned.
//
// The returned Handle carries:
//
//	Refs["namespace"]   → the scoped namespace name
//	Refs["secret"]      → the owning Secret name (for teardown + GC)
//	Refs["runner_pod"]  → runner Pod name (for WaitForExit)
//	Refs["proxy_pod"]   → proxy Pod name
//	Refs["network_name"] → "" (not used by the kube backend)
func (b *kubeBackend) Spawn(ctx context.Context, in backend.SpawnInput) (backend.Handle, error) {
	ns := kube.Namespace(in.Scope)

	if err := b.c.EnsureNamespace(ctx, in.Scope); err != nil {
		return backend.Handle{}, fmt.Errorf("kube backend: ensure namespace: %w", err)
	}

	// Build the per-spawn objects.
	secret := kube.ProxySecret(in)
	svc := kube.ProxyService(in)
	policies := []*networkingv1.NetworkPolicy{
		kube.RunnerEgressNetworkPolicy(in),
		kube.ProxyEgressNetworkPolicy(in),
	}

	// Derive the proxy Service DNS name: <svcName>.<namespace>.svc
	// This is the DNS name the runner Pod uses to reach the proxy.
	proxyServiceDNS := fmt.Sprintf("%s.%s.svc", svc.Name, ns)

	proxyPod := kube.ProxyPod(in, secret.Name)
	runnerPod := kube.RunnerPod(in, proxyServiceDNS)

	objs := kube.SpawnObjects{
		Secret:    secret,
		Service:   svc,
		Policies:  policies,
		ProxyPod:  proxyPod,
		RunnerPod: runnerPod,
	}

	if err := b.c.ApplySpawn(ctx, objs); err != nil {
		// Best-effort cleanup: delete the owning Secret which cascades GC.
		_ = b.c.DeleteSpawn(ctx, ns, secret.Name)
		return backend.Handle{}, fmt.Errorf("kube backend: apply spawn: %w", err)
	}

	return backend.Handle{
		SpawnID: in.SpawnID,
		Backend: "kube",
		Refs: map[string]string{
			"namespace":    ns,
			"secret":       secret.Name,
			"runner_pod":   runnerPod.Name,
			"proxy_pod":    proxyPod.Name,
			"network_name": "",
		},
	}, nil
}

// WaitForExit blocks until the runner pod transitions to a terminal phase or
// the timeout elapses.
//
// Phase → (exitCode, timedOut) mapping:
//
//	Succeeded → (0, false)
//	Failed    → (1, false)
//	timeout   → (-1, true)
//	other     → (1, false)  — unexpected terminal or empty phase after watch
func (b *kubeBackend) WaitForExit(ctx context.Context, h backend.Handle, timeout time.Duration) (int, bool) {
	ns := h.Refs["namespace"]
	podName := h.Refs["runner_pod"]

	phase, timedOut := b.c.WaitRunner(ctx, ns, podName, timeout)
	if timedOut {
		return -1, true
	}
	switch phase {
	case corev1.PodSucceeded:
		return 0, false
	case corev1.PodFailed:
		return 1, false
	default:
		// Empty phase (watch channel closed, re-list also failed) or an
		// unexpected terminal value — treat as failure.
		return 1, false
	}
}

// Teardown deletes the owning Secret for the spawn. The Kubernetes GC
// cascades deletion to the Service, NetworkPolicies, and both Pods via
// OwnerReferences set during ApplySpawn.
func (b *kubeBackend) Teardown(ctx context.Context, h backend.Handle, _ bool) error {
	ns := h.Refs["namespace"]
	secretName := h.Refs["secret"]
	if err := b.c.DeleteSpawn(ctx, ns, secretName); err != nil {
		return fmt.Errorf("kube backend: teardown spawn %q: %w", h.SpawnID, err)
	}
	return nil
}

// Reconcile lists all active runner pods in the scoped namespace and returns
// one Handle per spawn.  It calls kube.Client.ListSpawns which groups pods by
// spawn-id label and resolves the owning Secret name from OwnerReferences.
func (b *kubeBackend) Reconcile(ctx context.Context, scope string) ([]backend.Handle, error) {
	refs, err := b.c.ListSpawns(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("kube backend: reconcile scope %q: %w", scope, err)
	}

	handles := make([]backend.Handle, 0, len(refs))
	for _, ref := range refs {
		handles = append(handles, backend.Handle{
			SpawnID: ref.SpawnID,
			Backend: "kube",
			Refs: map[string]string{
				"namespace":    ref.Namespace,
				"secret":       ref.SecretName,
				"runner_pod":   ref.RunnerPod,
				"proxy_pod":    "",
				"network_name": "",
			},
		})
	}
	return handles, nil
}
