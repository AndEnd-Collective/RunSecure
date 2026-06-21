// Package kube contains pure builder functions that construct hardened
// Kubernetes objects from a backend.SpawnInput for a per-spawn runner+proxy
// stack. None of the functions here make API calls; they only build typed k8s
// objects ready to be submitted by a client.
//
// Security invariants enforced by every builder:
//   - Pod securityContext: runAsNonRoot=true, runAsUser=1001,
//     seccompProfile.type=RuntimeDefault.
//   - Container securityContext: allowPrivilegeEscalation=false,
//     capabilities drop ALL, readOnlyRootFilesystem=true, NOT privileged.
//   - automountServiceAccountToken=false on every Pod.
//   - No host namespaces (hostNetwork/hostPID/hostIPC all false).
//   - No hostPath volumes.
//   - RunnerPod.Spec.RestartPolicy = Never (one-shot CI runner).
//   - ProxySecret JIT key is projected with defaultMode 0o400.
//   - NetworkPolicies enforce default-deny + explicit allow-lists so the runner
//     can ONLY reach the proxy and the proxy can ONLY reach kube-dns + internet.
package kube

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
)

// Label key constants — the single source of truth for label names.
const (
	LabelScope   = "runsecure.io/scope"
	LabelRepo    = "runsecure.io/repo"
	LabelSpawnID = "runsecure.io/spawn-id"
	LabelRole    = "runsecure.io/role"

	RoleRunner = "runner"
	RoleProxy  = "proxy"

	// proxyPort is the Squid/HAProxy CONNECT port.
	proxyPort = int32(3128)
	// dnsPort is used for kube-dns and optional in-proxy dnsmasq.
	dnsPort = int32(53)

	// runnerUID is the non-root UID used for both runner and proxy containers
	// (matches the hardened image layer: UID 1001 is created in base.Dockerfile).
	runnerUID = int64(1001)

	// kubeDNSClusterIP is the well-known kube-dns cluster IP in standard
	// Kubernetes distributions. Used by ProxyEgressNetworkPolicy to explicitly
	// allow outbound DNS from the proxy pod.
	// TODO(egress): replace this with a dynamic look-up or a configurable field
	// once the egress package exposes parsed CIDRs (Phase 2 Task 5).
	kubeDNSClusterIP = "10.96.0.10/32"

	// worldCIDR is the catch-all for external internet egress in
	// ProxyEgressNetworkPolicy. The proxy enforces domain allow-lists at L7
	// (Squid); the NetworkPolicy layer cannot replicate that fidelity without
	// a per-domain CIDR list from the egress package. Using 0.0.0.0/0 here
	// is intentional: the L7 filter is the primary control, the NetworkPolicy
	// ensures the *runner* cannot bypass the proxy (which is enforced by
	// RunnerEgressNetworkPolicy, not this policy).
	//
	// TODO(egress): when the egress package exposes resolved CIDRs (Phase 2
	// Task 5), replace worldCIDR with the list of per-domain CIDRs so the
	// NetworkPolicy provides defence-in-depth at L3/L4 in addition to the L7
	// Squid allow-list. See internal/egress for the rendering logic.
	worldCIDR = "0.0.0.0/0"
)

// ──────────────────────────────────────────────────────────────────────────────
// Namespace
// ──────────────────────────────────────────────────────────────────────────────

// Namespace returns the Kubernetes namespace name for the given scope.
// Format: "runsecure-<scope>".
func Namespace(scope string) string {
	return "runsecure-" + scope
}

// ──────────────────────────────────────────────────────────────────────────────
// Labels
// ──────────────────────────────────────────────────────────────────────────────

// Labels returns the four standard runsecure label key/value pairs for an
// object belonging to the given spawn and playing the given role.
// The repo "/" separator is replaced with "_" to keep the label value valid.
func Labels(in backend.SpawnInput, role string) map[string]string {
	return map[string]string{
		LabelScope:   in.Scope,
		LabelRepo:    strings.ReplaceAll(in.Repo, "/", "_"),
		LabelSpawnID: in.SpawnID,
		LabelRole:    role,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

// ptr returns a pointer to the supplied value.
func ptr[T any](v T) *T { return &v }

// hardPodSecCtx returns the pod-level PodSecurityContext shared by every pod
// in the stack.
func hardPodSecCtx() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsNonRoot: ptr(true),
		RunAsUser:    ptr(runnerUID),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// hardContainerSecCtx returns the per-container SecurityContext shared by every
// container in the stack.
func hardContainerSecCtx() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		Privileged:               ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
}

// objectMeta builds a standard ObjectMeta for spawn objects.
func objectMeta(name, namespace string, labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

// spawnResourceName returns a deterministic name for a per-spawn resource with
// the given kind suffix.  Format: "rs-<kind>-<spawnID>".
func spawnResourceName(kind, spawnID string) string {
	return fmt.Sprintf("rs-%s-%s", kind, spawnID)
}

// ──────────────────────────────────────────────────────────────────────────────
// ProxySecret
// ──────────────────────────────────────────────────────────────────────────────

// ProxySecret builds the per-spawn Secret that carries the GitHub JIT config
// and rendered egress configs.  The JIT config key is projected with
// defaultMode 0o400 (read-only by owner) via the Secret's DefaultMode field.
//
// The Secret acts as the *owning* object for the spawn stack: deleting it
// cascades (via ownerReferences set on other objects) to remove all per-spawn
// resources.
func ProxySecret(in backend.SpawnInput) *corev1.Secret {
	ns := Namespace(in.Scope)
	name := spawnResourceName("secret", in.SpawnID)
	labels := Labels(in, RoleProxy)

	return &corev1.Secret{
		ObjectMeta: objectMeta(name, ns, labels),
		// defaultMode 0o400 — read-only by the owning UID; no group/world access.
		// Individual volumes that mount from this Secret should also specify mode 0o400.
		Immutable: ptr(false), // allow the orchestrator to patch egress configs
		StringData: map[string]string{
			"jit-config": in.JITConfigB64,
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ProxyPod
// ──────────────────────────────────────────────────────────────────────────────

// ProxyPod builds the proxy Pod (Squid + HAProxy + optional dnsmasq).
//
//   - 2 containers when EnableDNSMasq is false (squid, haproxy).
//   - 3 containers when EnableDNSMasq is true  (squid, haproxy, dnsmasq).
//
// The JIT config and rendered egress configs are mounted from secretName with
// mode 0o400.
func ProxyPod(in backend.SpawnInput, secretName string) *corev1.Pod {
	ns := Namespace(in.Scope)
	labels := Labels(in, RoleProxy)

	// Secret volume for JIT config + egress configs.
	secretVolume := corev1.Volume{
		Name: "jit-secret",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  secretName,
				DefaultMode: ptr(int32(0o400)),
			},
		},
	}
	// tmpfs for writable ephemeral state the proxy processes need.
	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory,
			},
		},
	}

	secretMount := corev1.VolumeMount{
		Name:      "jit-secret",
		MountPath: "/var/run/runsecure/secrets",
		ReadOnly:  true,
	}
	tmpMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: "/tmp",
		ReadOnly:  false,
	}

	squid := corev1.Container{
		Name:            "squid",
		Image:           in.ProxyImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: hardContainerSecCtx(),
		VolumeMounts:    []corev1.VolumeMount{secretMount, tmpMount},
		Ports: []corev1.ContainerPort{
			{Name: "squid", ContainerPort: proxyPort, Protocol: corev1.ProtocolTCP},
		},
	}
	haproxy := corev1.Container{
		Name:            "haproxy",
		Image:           in.ProxyImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: hardContainerSecCtx(),
		VolumeMounts:    []corev1.VolumeMount{secretMount, tmpMount},
		Args:            []string{"haproxy"},
	}

	containers := []corev1.Container{squid, haproxy}
	if in.EnableDNSMasq {
		dnsmasq := corev1.Container{
			Name:            "dnsmasq",
			Image:           in.ProxyImage,
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: hardContainerSecCtx(),
			VolumeMounts:    []corev1.VolumeMount{secretMount, tmpMount},
			Args:            []string{"dnsmasq"},
			Ports: []corev1.ContainerPort{
				{Name: "dns-udp", ContainerPort: dnsPort, Protocol: corev1.ProtocolUDP},
				{Name: "dns-tcp", ContainerPort: dnsPort, Protocol: corev1.ProtocolTCP},
			},
		}
		containers = append(containers, dnsmasq)
	}

	return &corev1.Pod{
		ObjectMeta: objectMeta(spawnResourceName("proxy", in.SpawnID), ns, labels),
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr(false),
			HostNetwork:                  false,
			HostPID:                      false,
			HostIPC:                      false,
			SecurityContext:              hardPodSecCtx(),
			Volumes:                      []corev1.Volume{secretVolume, tmpVolume},
			Containers:                   containers,
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RunnerPod
// ──────────────────────────────────────────────────────────────────────────────

// RunnerPod builds the runner Pod with a single container.
//
//   - HTTP_PROXY / HTTPS_PROXY / http_proxy / https_proxy point to
//     http://<proxyServiceDNS>:3128.
//   - NO_PROXY excludes the cluster-local address space so kube API calls are
//     not routed through the proxy.
//   - restartPolicy: Never (one-shot CI runner; GH Actions expects exit code).
func RunnerPod(in backend.SpawnInput, proxyServiceDNS string) *corev1.Pod {
	ns := Namespace(in.Scope)
	labels := Labels(in, RoleRunner)

	proxyURL := fmt.Sprintf("http://%s:%d", proxyServiceDNS, proxyPort)
	noProxy := "localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc.cluster.local,.cluster.local"

	proxyEnv := []corev1.EnvVar{
		{Name: "HTTP_PROXY", Value: proxyURL},
		{Name: "HTTPS_PROXY", Value: proxyURL},
		{Name: "http_proxy", Value: proxyURL},
		{Name: "https_proxy", Value: proxyURL},
		{Name: "NO_PROXY", Value: noProxy},
		{Name: "no_proxy", Value: noProxy},
	}

	// tmpfs so the runner can write to /tmp (readOnlyRootFilesystem=true).
	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory,
			},
		},
	}
	tmpMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: "/tmp",
		ReadOnly:  false,
	}

	runner := corev1.Container{
		Name:            "runner",
		Image:           in.RunnerImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: hardContainerSecCtx(),
		Env:             proxyEnv,
		VolumeMounts:    []corev1.VolumeMount{tmpMount},
	}

	return &corev1.Pod{
		ObjectMeta: objectMeta(spawnResourceName("runner", in.SpawnID), ns, labels),
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr(false),
			HostNetwork:                  false,
			HostPID:                      false,
			HostIPC:                      false,
			SecurityContext:              hardPodSecCtx(),
			Volumes:                      []corev1.Volume{tmpVolume},
			Containers:                   []corev1.Container{runner},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ProxyService
// ──────────────────────────────────────────────────────────────────────────────

// ProxyService builds the ClusterIP Service that exposes the proxy stack to the
// runner Pod.  Ports included:
//   - 3128/TCP  — Squid/HAProxy HTTP CONNECT port (always).
//   - 53/TCP+UDP — dnsmasq (only when EnableDNSMasq is true).
//   - Each port in TCPEgressPorts (e.g. 443 for direct TLS passthrough).
func ProxyService(in backend.SpawnInput) *corev1.Service {
	ns := Namespace(in.Scope)
	labels := Labels(in, RoleProxy)

	selector := map[string]string{
		LabelRole:    RoleProxy,
		LabelSpawnID: in.SpawnID,
	}

	ports := []corev1.ServicePort{
		{
			Name:       "squid",
			Protocol:   corev1.ProtocolTCP,
			Port:       proxyPort,
			TargetPort: intstr.FromInt32(proxyPort),
		},
	}

	// Optional dnsmasq DNS port.
	if in.EnableDNSMasq {
		ports = append(ports,
			corev1.ServicePort{
				Name:       "dns-tcp",
				Protocol:   corev1.ProtocolTCP,
				Port:       dnsPort,
				TargetPort: intstr.FromInt32(dnsPort),
			},
			corev1.ServicePort{
				Name:       "dns-udp",
				Protocol:   corev1.ProtocolUDP,
				Port:       dnsPort,
				TargetPort: intstr.FromInt32(dnsPort),
			},
		)
	}

	// TCP egress ports for direct passthrough (e.g. SSH, custom registries).
	seen := map[int32]bool{}
	for _, p := range in.TCPEgressPorts {
		port := int32(p)
		if seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, corev1.ServicePort{
			Name:       fmt.Sprintf("tcp-%d", port),
			Protocol:   corev1.ProtocolTCP,
			Port:       port,
			TargetPort: intstr.FromInt32(port),
		})
	}

	return &corev1.Service{
		ObjectMeta: objectMeta(spawnResourceName("proxy-svc", in.SpawnID), ns, labels),
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: selector,
			Ports:    ports,
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// DefaultDenyNetworkPolicy
// ──────────────────────────────────────────────────────────────────────────────

// DefaultDenyNetworkPolicy returns a namespace-wide default-deny NetworkPolicy.
// It uses an empty podSelector (selects all pods) and declares both Ingress and
// Egress policyTypes with no allow rules, effectively denying all traffic to
// and from every pod in the namespace unless another policy permits it.
func DefaultDenyNetworkPolicy(scope string) *networkingv1.NetworkPolicy {
	ns := Namespace(scope)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-all",
			Namespace: ns,
			Labels: map[string]string{
				LabelScope: scope,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Empty PodSelector selects ALL pods in the namespace.
			PodSelector: metav1.LabelSelector{},
			// Listing both types with no Ingress/Egress rules = deny all.
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// No Ingress or Egress rules — all traffic denied.
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RunnerEgressNetworkPolicy
// ──────────────────────────────────────────────────────────────────────────────

// RunnerEgressNetworkPolicy returns a NetworkPolicy that restricts the runner
// Pod to egress ONLY to the proxy Pod on the explicitly listed ports:
//
//   - 3128/TCP   — HTTP CONNECT (always).
//   - 53/UDP+TCP  — dnsmasq (only when EnableDNSMasq is true).
//   - Each port in TCPEgressPorts.
//
// All other egress from the runner is denied by the DefaultDenyNetworkPolicy.
// No Ingress rule is created — the runner must not accept inbound connections.
func RunnerEgressNetworkPolicy(in backend.SpawnInput) *networkingv1.NetworkPolicy {
	ns := Namespace(in.Scope)
	labels := Labels(in, RoleRunner)

	// Build the list of ports the runner may use to reach the proxy.
	tcpProto := corev1.ProtocolTCP
	udpProto := corev1.ProtocolUDP

	ports := []networkingv1.NetworkPolicyPort{
		{
			Protocol: &tcpProto,
			Port:     ptrIntStr(proxyPort),
		},
	}
	if in.EnableDNSMasq {
		ports = append(ports,
			networkingv1.NetworkPolicyPort{Protocol: &udpProto, Port: ptrIntStr(dnsPort)},
			networkingv1.NetworkPolicyPort{Protocol: &tcpProto, Port: ptrIntStr(dnsPort)},
		)
	}
	for _, p := range in.TCPEgressPorts {
		port := int32(p)
		ports = append(ports, networkingv1.NetworkPolicyPort{
			Protocol: &tcpProto,
			Port:     ptrIntStr(port),
		})
	}

	// The egress rule targets pods with role=proxy in the same spawn.
	proxyPeer := networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				LabelRole:    RoleProxy,
				LabelSpawnID: in.SpawnID,
			},
		},
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: objectMeta(spawnResourceName("runner-egress", in.SpawnID), ns, labels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					LabelRole:    RoleRunner,
					LabelSpawnID: in.SpawnID,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To:    []networkingv1.NetworkPolicyPeer{proxyPeer},
					Ports: ports,
				},
			},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ProxyEgressNetworkPolicy
// ──────────────────────────────────────────────────────────────────────────────

// ProxyEgressNetworkPolicy returns a NetworkPolicy that allows the proxy Pod to:
//
//  1. Reach kube-dns on port 53 (TCP+UDP) for DNS resolution.
//  2. Reach the external internet on any port (0.0.0.0/0) so Squid can proxy
//     runner CONNECT requests.
//
// # Security rationale for the broad internet egress rule
//
// The proxy enforces a domain allow-list at L7 via Squid's ACLs. The
// NetworkPolicy here cannot replicate that fidelity without a per-domain CIDR
// list. Using 0.0.0.0/0 is acceptable because:
//   - The runner is restricted to "proxy only" by RunnerEgressNetworkPolicy —
//     it cannot bypass the proxy to reach the internet directly.
//   - The proxy's Squid config (rendered by internal/egress) enforces L7
//     allow-lists; any attempt by a compromised proxy process to reach a
//     non-allow-listed domain is rejected by Squid itself.
//
// TODO(egress): when internal/egress exposes resolved CIDRs (Phase 2 Task 5),
// replace the 0.0.0.0/0 peer with the explicit CIDR list for defence-in-depth.
func ProxyEgressNetworkPolicy(in backend.SpawnInput) *networkingv1.NetworkPolicy {
	ns := Namespace(in.Scope)
	labels := Labels(in, RoleProxy)

	tcpProto := corev1.ProtocolTCP
	udpProto := corev1.ProtocolUDP

	// Rule 1: DNS to kube-dns (well-known cluster IP).
	dnsRule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				IPBlock: &networkingv1.IPBlock{
					CIDR: kubeDNSClusterIP,
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: &udpProto, Port: ptrIntStr(dnsPort)},
			{Protocol: &tcpProto, Port: ptrIntStr(dnsPort)},
		},
	}

	// Rule 2: internet egress (all IPs minus private RFC1918 ranges to avoid
	// routing cluster traffic via this rule).
	// The Squid L7 allow-list is the authoritative control; this rule provides
	// network-layer reachability.
	internetRule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				IPBlock: &networkingv1.IPBlock{
					CIDR: worldCIDR,
					Except: []string{
						"10.0.0.0/8",
						"172.16.0.0/12",
						"192.168.0.0/16",
					},
				},
			},
		},
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: objectMeta(spawnResourceName("proxy-egress", in.SpawnID), ns, labels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					LabelRole:    RoleProxy,
					LabelSpawnID: in.SpawnID,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				dnsRule,
				internetRule,
			},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// OwnerRef
// ──────────────────────────────────────────────────────────────────────────────

// OwnerRef returns an OwnerReference pointing at the given Secret with
// controller=true and blockOwnerDeletion=true.  When set on all per-spawn
// objects (Service, NetworkPolicies, Pods), deleting the Secret causes the
// Kubernetes garbage collector to cascade-delete the entire spawn stack.
func OwnerRef(secret *corev1.Secret) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         "v1",
		Kind:               "Secret",
		Name:               secret.Name,
		UID:                secret.UID,
		Controller:         ptr(true),
		BlockOwnerDeletion: ptr(true),
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

// ptrIntStr returns a pointer to an IntOrString wrapping the given integer port.
func ptrIntStr(port int32) *intstr.IntOrString {
	v := intstr.FromInt32(port)
	return &v
}
