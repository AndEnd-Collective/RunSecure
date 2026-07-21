// Package kube implements backend.Backend using Kubernetes: each spawn is
// realised as a runner Pod + proxy Pod + ClusterIP Service + per-spawn
// NetworkPolicies + a per-spawn Secret (the GC owner) inside a per-scope
// namespace.  The kube.Client wrapper handles all API calls; the kube object
// builders produce the typed k8s objects from a backend.SpawnInput.
package kube

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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
	dnsPrefix, err := netip.ParsePrefix(in.KubeDNSCIDR)
	if err != nil || !dnsPrefix.Addr().Is4() || dnsPrefix.Bits() != 32 || dnsPrefix != dnsPrefix.Masked() {
		return backend.Handle{}, errors.New("kube backend: KubeDNSCIDR must be an exact IPv4 /32")
	}

	if err := b.c.EnsureNamespace(ctx, in.Scope); err != nil {
		return backend.Handle{}, fmt.Errorf("kube backend: ensure namespace: %w", err)
	}

	// The proxy supervisor cannot start safely with a missing or empty config.
	// Fail before creating any per-spawn API objects rather than letting a Pod
	// crash-loop with a partially projected Secret.
	readEgressFile := func(name string) ([]byte, error) {
		if in.EgressConfigDir == "" {
			return nil, errors.New("egress config directory is required")
		}
		path := filepath.Join(in.EgressConfigDir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if len(content) == 0 {
			return nil, fmt.Errorf("read %s: config is empty", name)
		}
		return content, nil
	}
	squidBytes, err := readEgressFile("squid.conf")
	if err != nil {
		return backend.Handle{}, fmt.Errorf("kube backend: %w", err)
	}
	haproxyBytes, err := readEgressFile("haproxy.cfg")
	if err != nil {
		return backend.Handle{}, fmt.Errorf("kube backend: %w", err)
	}
	var dnsmasqBytes []byte
	if in.EnableDNSMasq {
		dnsmasqBytes, err = readEgressFile("dnsmasq.conf")
		if err != nil {
			return backend.Handle{}, fmt.Errorf("kube backend: %w", err)
		}
	}

	// Build the per-spawn objects.
	secret := kube.SpawnSecret(in, squidBytes, haproxyBytes, dnsmasqBytes)
	svc := kube.ProxyService(in)
	policies := []*networkingv1.NetworkPolicy{
		kube.RunnerEgressNetworkPolicy(in),
		kube.ProxyEgressNetworkPolicy(in),
		kube.ProxyIngressNetworkPolicy(in),
	}

	// Derive the proxy Service DNS name: <svcName>.<namespace>.svc
	// This is the DNS name the runner Pod uses to reach the proxy.
	proxyServiceDNS := fmt.Sprintf("%s.%s.svc", svc.Name, ns)

	proxyPod := kube.ProxyPod(in, secret.Name)
	runnerPod := kube.RunnerPod(in, secret.Name, proxyServiceDNS)

	objs := kube.SpawnObjects{
		Secret:    secret,
		Service:   svc,
		Policies:  policies,
		ProxyPod:  proxyPod,
		RunnerPod: runnerPod,
	}
	h := backend.Handle{
		SpawnID: in.SpawnID,
		Backend: "kube",
		Refs: map[string]string{
			"namespace":         ns,
			"secret":            secret.Name,
			"runner_pod":        runnerPod.Name,
			"proxy_pod":         proxyPod.Name,
			"network_name":      "",
			"egress_config_dir": in.EgressConfigDir,
			"repo_label":        kube.RepoLabel(in.Repo),
		},
	}

	if err := b.c.ApplySpawn(ctx, objs); err != nil {
		applyErr := fmt.Errorf("kube backend: apply spawn: %w", err)
		// Deleting the owning Secret is the exact rollback. If confirmation
		// fails, return the handle so the orchestrator retains teardown debt
		// and retries instead of releasing capacity around leaked objects.
		if cleanupErr := b.c.DeleteSpawn(
			ctx, ns, secret.Name, in.SpawnID, kube.RepoLabel(in.Repo),
		); cleanupErr != nil {
			return h, errors.Join(applyErr,
				fmt.Errorf("kube backend: rollback spawn: %w", cleanupErr))
		}
		return backend.Handle{}, applyErr
	}

	return h, nil
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
	repoLabel := h.Refs["repo_label"]
	var cleanupErrors []error
	if err := b.c.DeleteSpawn(ctx, ns, secretName, h.SpawnID, repoLabel); err != nil {
		cleanupErrors = append(cleanupErrors,
			fmt.Errorf("kube backend: teardown spawn %q: %w", h.SpawnID, err))
	}
	if egressDir := h.Refs["egress_config_dir"]; egressDir != "" {
		if err := os.RemoveAll(egressDir); err != nil {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("kube backend: remove egress config %q: %w", egressDir, err))
		}
	}
	return errors.Join(cleanupErrors...)
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
				"repo_label":   ref.RepoLabel,
			},
		})
	}
	return handles, nil
}
