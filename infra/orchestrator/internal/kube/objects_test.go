package kube_test

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
)

// testInput returns a fully-populated SpawnInput for use in table tests.
func testInput() backend.SpawnInput {
	return backend.SpawnInput{
		Scope:              "ci",
		Repo:               "acme/widget",
		SpawnID:            "spawn-abc123",
		RunnerImage:        "ghcr.io/acme/runner@sha256:aaaa",
		ProxyImage:         "ghcr.io/acme/proxy@sha256:bbbb",
		SeccompProfilePath: "/etc/seccomp/node-runner.json",
		ResourcesMemory:    2147483648,
		ResourcesNanoCPUs:  2000000000,
		ResourcesPIDs:      512,
		JITConfigB64:       "base64jitconfig==",
		EgressConfigDir:    "/var/run/runsecure/egress/spawn-abc123",
		EnableDNSMasq:      true,
		Labels:             []string{"runsecure.scope=ci"},
		TCPEgressPorts:     []int{443, 8080},
	}
}

// -------------------------------------------------------------------
// Namespace
// -------------------------------------------------------------------

func TestNamespace(t *testing.T) {
	tests := []struct {
		scope string
		want  string
	}{
		{"ci", "runsecure-ci"},
		{"prod", "runsecure-prod"},
		{"my-scope", "runsecure-my-scope"},
	}
	for _, tt := range tests {
		got := kube.Namespace(tt.scope)
		if got != tt.want {
			t.Errorf("Namespace(%q) = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

// -------------------------------------------------------------------
// Labels
// -------------------------------------------------------------------

func TestLabels_AllFourKeys(t *testing.T) {
	in := testInput()
	for _, role := range []string{"runner", "proxy"} {
		lbls := kube.Labels(in, role)
		required := []string{
			"runsecure.io/scope",
			"runsecure.io/repo",
			"runsecure.io/spawn-id",
			"runsecure.io/role",
		}
		for _, k := range required {
			if _, ok := lbls[k]; !ok {
				t.Errorf("Labels(%q): missing key %q", role, k)
			}
		}
		if lbls["runsecure.io/scope"] != in.Scope {
			t.Errorf("Labels(%q): scope = %q, want %q", role, lbls["runsecure.io/scope"], in.Scope)
		}
		if lbls["runsecure.io/repo"] != strings.ReplaceAll(in.Repo, "/", "_") {
			t.Errorf("Labels(%q): repo value mismatch", role)
		}
		if lbls["runsecure.io/spawn-id"] != in.SpawnID {
			t.Errorf("Labels(%q): spawn-id = %q, want %q", role, lbls["runsecure.io/spawn-id"], in.SpawnID)
		}
		if lbls["runsecure.io/role"] != role {
			t.Errorf("Labels(%q): role = %q, want %q", role, lbls["runsecure.io/role"], role)
		}
	}
}

// -------------------------------------------------------------------
// ProxySecret
// -------------------------------------------------------------------

func TestProxySecret_JITKeyDefaultMode(t *testing.T) {
	in := testInput()
	s := kube.ProxySecret(in)

	if s.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("ProxySecret namespace = %q, want %q", s.Namespace, kube.Namespace(in.Scope))
	}
	if len(s.StringData) == 0 && len(s.Data) == 0 {
		t.Errorf("ProxySecret has no data")
	}
	// JIT config key must be present in StringData or Data.
	_, hasJIT := s.StringData["jit-config"]
	if !hasJIT {
		if _, ok := s.Data["jit-config"]; !ok {
			t.Errorf("ProxySecret missing jit-config key")
		}
	}
	// Annotations must record the spawn-id.
	if s.Labels["runsecure.io/spawn-id"] != in.SpawnID {
		t.Errorf("ProxySecret missing spawn-id label")
	}
}

func TestProxySecret_HasRunSecureLabels(t *testing.T) {
	in := testInput()
	s := kube.ProxySecret(in)
	if s.Labels["runsecure.io/role"] != "proxy" {
		t.Errorf("ProxySecret role label = %q, want proxy", s.Labels["runsecure.io/role"])
	}
}

// -------------------------------------------------------------------
// ProxyPod
// -------------------------------------------------------------------

func TestProxyPod_SecurityContext(t *testing.T) {
	in := testInput()
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)

	assertPodSecurity(t, "ProxyPod", pod)
}

func TestProxyPod_ContainerCount_DNSMasqOn(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = true
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if len(pod.Spec.Containers) != 3 {
		t.Errorf("ProxyPod with dnsmasq: got %d containers, want 3", len(pod.Spec.Containers))
	}
}

func TestProxyPod_ContainerCount_DNSMasqOff(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = false
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if len(pod.Spec.Containers) != 2 {
		t.Errorf("ProxyPod without dnsmasq: got %d containers, want 2", len(pod.Spec.Containers))
	}
}

func TestProxyPod_AutomountSATokenFalse(t *testing.T) {
	in := testInput()
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Errorf("ProxyPod: automountServiceAccountToken must be explicitly false")
	}
}

func TestProxyPod_NoHostNamespaces(t *testing.T) {
	in := testInput()
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		t.Errorf("ProxyPod: host namespaces must not be enabled")
	}
}

func TestProxyPod_Labels(t *testing.T) {
	in := testInput()
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if pod.Labels["runsecure.io/role"] != "proxy" {
		t.Errorf("ProxyPod: role label = %q, want proxy", pod.Labels["runsecure.io/role"])
	}
}

func TestProxyPod_Namespace(t *testing.T) {
	in := testInput()
	pod := kube.ProxyPod(in, "rs-secret-"+in.SpawnID)
	if pod.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("ProxyPod namespace = %q, want %q", pod.Namespace, kube.Namespace(in.Scope))
	}
}

// -------------------------------------------------------------------
// RunnerPod
// -------------------------------------------------------------------

func TestRunnerPod_SecurityContext(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "rs-proxy-svc-"+in.SpawnID+"."+kube.Namespace(in.Scope)+".svc.cluster.local")
	assertPodSecurity(t, "RunnerPod", pod)
}

func TestRunnerPod_HTTPProxy(t *testing.T) {
	in := testInput()
	proxyDNS := "rs-proxy-svc-spawn-abc123.runsecure-ci.svc.cluster.local"
	pod := kube.RunnerPod(in, proxyDNS)

	wantProxy := "http://" + proxyDNS + ":3128"
	envMap := containerEnvMap(pod.Spec.Containers[0])

	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if v, ok := envMap[key]; !ok || v != wantProxy {
			t.Errorf("RunnerPod env %s = %q, want %q", key, v, wantProxy)
		}
	}
}

func TestRunnerPod_NoProxyEnv(t *testing.T) {
	in := testInput()
	proxyDNS := "rs-proxy-svc-spawn-abc123.runsecure-ci.svc.cluster.local"
	pod := kube.RunnerPod(in, proxyDNS)
	envMap := containerEnvMap(pod.Spec.Containers[0])
	if v, ok := envMap["NO_PROXY"]; !ok || v == "" {
		t.Errorf("RunnerPod: NO_PROXY env must be set, got %q (present=%v)", v, ok)
	}
}

func TestRunnerPod_RestartPolicyNever(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("RunnerPod restartPolicy = %q, want Never", pod.Spec.RestartPolicy)
	}
}

func TestRunnerPod_AutomountSATokenFalse(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Errorf("RunnerPod: automountServiceAccountToken must be explicitly false")
	}
}

func TestRunnerPod_NoHostNamespaces(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		t.Errorf("RunnerPod: host namespaces must not be enabled")
	}
}

func TestRunnerPod_SingleContainer(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if len(pod.Spec.Containers) != 1 {
		t.Errorf("RunnerPod: got %d containers, want 1", len(pod.Spec.Containers))
	}
}

func TestRunnerPod_Labels(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if pod.Labels["runsecure.io/role"] != "runner" {
		t.Errorf("RunnerPod: role label = %q, want runner", pod.Labels["runsecure.io/role"])
	}
}

func TestRunnerPod_Namespace(t *testing.T) {
	in := testInput()
	pod := kube.RunnerPod(in, "proxy.svc")
	if pod.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("RunnerPod namespace = %q, want %q", pod.Namespace, kube.Namespace(in.Scope))
	}
}

// -------------------------------------------------------------------
// ProxyService
// -------------------------------------------------------------------

func TestProxyService_Port3128(t *testing.T) {
	in := testInput()
	svc := kube.ProxyService(in)
	if !hasServicePort(svc, 3128) {
		t.Errorf("ProxyService: missing port 3128")
	}
}

func TestProxyService_TCPEgressPorts(t *testing.T) {
	in := testInput()
	svc := kube.ProxyService(in)
	for _, p := range in.TCPEgressPorts {
		if !hasServicePort(svc, int32(p)) {
			t.Errorf("ProxyService: missing TCPEgressPort %d", p)
		}
	}
}

func TestProxyService_DNSMasqPort53(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = true
	svc := kube.ProxyService(in)
	if !hasServicePort(svc, 53) {
		t.Errorf("ProxyService: missing port 53 when dnsmasq enabled")
	}
}

func TestProxyService_NoDNSPortWhenDisabled(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = false
	svc := kube.ProxyService(in)
	if hasServicePort(svc, 53) {
		t.Errorf("ProxyService: port 53 must not appear when dnsmasq disabled")
	}
}

func TestProxyService_SelectorMatchesProxyRole(t *testing.T) {
	in := testInput()
	svc := kube.ProxyService(in)
	if svc.Spec.Selector["runsecure.io/role"] != "proxy" {
		t.Errorf("ProxyService selector role = %q, want proxy", svc.Spec.Selector["runsecure.io/role"])
	}
	if svc.Spec.Selector["runsecure.io/spawn-id"] != in.SpawnID {
		t.Errorf("ProxyService selector spawn-id = %q, want %q", svc.Spec.Selector["runsecure.io/spawn-id"], in.SpawnID)
	}
}

func TestProxyService_ClusterIP(t *testing.T) {
	in := testInput()
	svc := kube.ProxyService(in)
	if svc.Spec.Type != "" && svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("ProxyService type = %q, want ClusterIP (or empty default)", svc.Spec.Type)
	}
}

func TestProxyService_Namespace(t *testing.T) {
	in := testInput()
	svc := kube.ProxyService(in)
	if svc.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("ProxyService namespace = %q, want %q", svc.Namespace, kube.Namespace(in.Scope))
	}
}

// TestProxyService_DuplicateTCPEgressPortsDeduped verifies that when
// TCPEgressPorts contains duplicate values only one ServicePort is emitted
// per unique port number (exercising the seen[port] dedup branch).
func TestProxyService_DuplicateTCPEgressPortsDeduped(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = false
	// Provide duplicates: port 9000 appears twice, port 8443 once.
	in.TCPEgressPorts = []int{9000, 8443, 9000}

	svc := kube.ProxyService(in)

	// Count how many times port 9000 appears.
	count9000 := 0
	for _, p := range svc.Spec.Ports {
		if p.Port == 9000 {
			count9000++
		}
	}
	if count9000 != 1 {
		t.Errorf("ProxyService: port 9000 should appear exactly once after dedup, got %d", count9000)
	}
	// Port 8443 must appear exactly once.
	if !hasServicePort(svc, 8443) {
		t.Errorf("ProxyService: port 8443 must be present")
	}
	// Port 53 must be absent (dnsmasq disabled).
	if hasServicePort(svc, 53) {
		t.Errorf("ProxyService: port 53 must not appear when dnsmasq disabled")
	}
}

// TestProxyService_EmptyTCPEgressPorts verifies that only the squid port (3128)
// is present when TCPEgressPorts is empty and dnsmasq is off.
func TestProxyService_EmptyTCPEgressPorts(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = false
	in.TCPEgressPorts = nil

	svc := kube.ProxyService(in)

	if len(svc.Spec.Ports) != 1 {
		t.Errorf("ProxyService with no egress ports: got %d ports, want 1 (squid only)", len(svc.Spec.Ports))
	}
	if !hasServicePort(svc, 3128) {
		t.Errorf("ProxyService: squid port 3128 must always be present")
	}
}

// TestProxyService_DNSMasqAndMultipleTCPPorts checks the port set when dnsmasq
// is enabled alongside several TCP egress ports (no duplicates).
func TestProxyService_DNSMasqAndMultipleTCPPorts(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = true
	in.TCPEgressPorts = []int{443, 8080, 22}

	svc := kube.ProxyService(in)

	// squid + dns-tcp + dns-udp + 3 TCP egress = 6 ports total.
	if len(svc.Spec.Ports) != 6 {
		t.Errorf("ProxyService: got %d ports, want 6", len(svc.Spec.Ports))
	}
	for _, p := range []int32{3128, 53, 443, 8080, 22} {
		if !hasServicePort(svc, p) {
			t.Errorf("ProxyService: missing expected port %d", p)
		}
	}
}

// -------------------------------------------------------------------
// DefaultDenyNetworkPolicy
// -------------------------------------------------------------------

func TestDefaultDenyNetworkPolicy_EmptyPodSelector(t *testing.T) {
	pol := kube.DefaultDenyNetworkPolicy("ci")
	if pol.Spec.PodSelector.MatchLabels != nil || pol.Spec.PodSelector.MatchExpressions != nil {
		t.Errorf("DefaultDeny: podSelector must be empty (selects all pods)")
	}
}

func TestDefaultDenyNetworkPolicy_BothPolicyTypes(t *testing.T) {
	pol := kube.DefaultDenyNetworkPolicy("ci")
	types := pol.Spec.PolicyTypes
	hasIngress, hasEgress := false, false
	for _, pt := range types {
		if pt == networkingv1.PolicyTypeIngress {
			hasIngress = true
		}
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
	}
	if !hasIngress || !hasEgress {
		t.Errorf("DefaultDeny: policyTypes must include both Ingress and Egress, got %v", types)
	}
}

func TestDefaultDenyNetworkPolicy_NoAllowedEgress(t *testing.T) {
	pol := kube.DefaultDenyNetworkPolicy("ci")
	if len(pol.Spec.Egress) != 0 {
		t.Errorf("DefaultDeny: egress rules must be empty, got %d", len(pol.Spec.Egress))
	}
}

func TestDefaultDenyNetworkPolicy_NoAllowedIngress(t *testing.T) {
	pol := kube.DefaultDenyNetworkPolicy("ci")
	if len(pol.Spec.Ingress) != 0 {
		t.Errorf("DefaultDeny: ingress rules must be empty, got %d", len(pol.Spec.Ingress))
	}
}

func TestDefaultDenyNetworkPolicy_Namespace(t *testing.T) {
	pol := kube.DefaultDenyNetworkPolicy("ci")
	if pol.Namespace != kube.Namespace("ci") {
		t.Errorf("DefaultDeny namespace = %q, want %q", pol.Namespace, kube.Namespace("ci"))
	}
}

// -------------------------------------------------------------------
// RunnerEgressNetworkPolicy
// -------------------------------------------------------------------

func TestRunnerEgressNetworkPolicy_EgressOnly(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)

	// Must have Egress policyType
	hasEgress := false
	for _, pt := range pol.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
		if pt == networkingv1.PolicyTypeIngress {
			t.Errorf("RunnerEgress: must not have Ingress policyType")
		}
	}
	if !hasEgress {
		t.Errorf("RunnerEgress: missing Egress policyType")
	}
}

func TestRunnerEgressNetworkPolicy_ToProxyOnly(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)

	if len(pol.Spec.Egress) == 0 {
		t.Fatalf("RunnerEgress: no egress rules")
	}
	// All peers must select role=proxy and the matching spawn-id.
	for _, rule := range pol.Spec.Egress {
		for _, peer := range rule.To {
			if peer.PodSelector == nil {
				t.Errorf("RunnerEgress: egress peer must have podSelector, got %+v", peer)
				continue
			}
			if peer.PodSelector.MatchLabels["runsecure.io/role"] != "proxy" {
				t.Errorf("RunnerEgress: peer role = %q, want proxy", peer.PodSelector.MatchLabels["runsecure.io/role"])
			}
		}
	}
}

func TestRunnerEgressNetworkPolicy_Port3128(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)
	if !networkPolicyHasPort(pol.Spec.Egress, 3128) {
		t.Errorf("RunnerEgress: missing port 3128")
	}
}

func TestRunnerEgressNetworkPolicy_TCPEgressPorts(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)
	for _, p := range in.TCPEgressPorts {
		if !networkPolicyHasPort(pol.Spec.Egress, int32(p)) {
			t.Errorf("RunnerEgress: missing TCPEgressPort %d", p)
		}
	}
}

func TestRunnerEgressNetworkPolicy_DNSMasqPort53(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = true
	pol := kube.RunnerEgressNetworkPolicy(in)
	if !networkPolicyHasPort(pol.Spec.Egress, 53) {
		t.Errorf("RunnerEgress: missing port 53 when dnsmasq enabled")
	}
}

func TestRunnerEgressNetworkPolicy_NoDNSPortWhenDisabled(t *testing.T) {
	in := testInput()
	in.EnableDNSMasq = false
	pol := kube.RunnerEgressNetworkPolicy(in)
	if networkPolicyHasPort(pol.Spec.Egress, 53) {
		t.Errorf("RunnerEgress: port 53 must not appear when dnsmasq disabled")
	}
}

func TestRunnerEgressNetworkPolicy_PodSelectorIsRunner(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)
	if pol.Spec.PodSelector.MatchLabels["runsecure.io/role"] != "runner" {
		t.Errorf("RunnerEgress: podSelector role = %q, want runner", pol.Spec.PodSelector.MatchLabels["runsecure.io/role"])
	}
}

func TestRunnerEgressNetworkPolicy_Namespace(t *testing.T) {
	in := testInput()
	pol := kube.RunnerEgressNetworkPolicy(in)
	if pol.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("RunnerEgress namespace = %q, want %q", pol.Namespace, kube.Namespace(in.Scope))
	}
}

// -------------------------------------------------------------------
// ProxyEgressNetworkPolicy
// -------------------------------------------------------------------

func TestProxyEgressNetworkPolicy_PodSelectorIsProxy(t *testing.T) {
	in := testInput()
	pol := kube.ProxyEgressNetworkPolicy(in)
	if pol.Spec.PodSelector.MatchLabels["runsecure.io/role"] != "proxy" {
		t.Errorf("ProxyEgress: podSelector role = %q, want proxy", pol.Spec.PodSelector.MatchLabels["runsecure.io/role"])
	}
}

func TestProxyEgressNetworkPolicy_HasEgressType(t *testing.T) {
	in := testInput()
	pol := kube.ProxyEgressNetworkPolicy(in)
	hasEgress := false
	for _, pt := range pol.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
	}
	if !hasEgress {
		t.Errorf("ProxyEgress: missing Egress policyType")
	}
}

func TestProxyEgressNetworkPolicy_AllowsDNS(t *testing.T) {
	in := testInput()
	pol := kube.ProxyEgressNetworkPolicy(in)
	// Must have a rule that allows port 53 (kube-dns).
	if !networkPolicyHasPort(pol.Spec.Egress, 53) {
		t.Errorf("ProxyEgress: missing port 53 (kube-dns)")
	}
}

func TestProxyEgressNetworkPolicy_AllowsInternetEgress(t *testing.T) {
	in := testInput()
	pol := kube.ProxyEgressNetworkPolicy(in)
	// Must have at least one rule with no podSelector/namespaceSelector (i.e. IPBlock
	// or empty peer = allows world). This verifies the proxy can reach the allowlist.
	hasWorldRule := false
	for _, rule := range pol.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				hasWorldRule = true
			}
			// empty To slice also counts (allows all destinations)
		}
		if len(rule.To) == 0 {
			hasWorldRule = true
		}
	}
	if !hasWorldRule {
		t.Errorf("ProxyEgress: must have a rule permitting external internet egress (IPBlock or empty To)")
	}
}

func TestProxyEgressNetworkPolicy_Namespace(t *testing.T) {
	in := testInput()
	pol := kube.ProxyEgressNetworkPolicy(in)
	if pol.Namespace != kube.Namespace(in.Scope) {
		t.Errorf("ProxyEgress namespace = %q, want %q", pol.Namespace, kube.Namespace(in.Scope))
	}
}

// -------------------------------------------------------------------
// OwnerRef
// -------------------------------------------------------------------

func TestOwnerRef_Fields(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rs-secret-spawn-abc123",
			UID:  "uid-1234",
		},
	}
	ref := kube.OwnerRef(s)
	if ref.Name != s.Name {
		t.Errorf("OwnerRef name = %q, want %q", ref.Name, s.Name)
	}
	if ref.UID != s.UID {
		t.Errorf("OwnerRef UID = %q, want %q", ref.UID, s.UID)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Errorf("OwnerRef: Controller must be true")
	}
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Errorf("OwnerRef: BlockOwnerDeletion must be true")
	}
}

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

// assertPodSecurity checks all mandatory security properties on a Pod.
func assertPodSecurity(t *testing.T, name string, pod *corev1.Pod) {
	t.Helper()

	// Pod-level: automountServiceAccountToken must be false.
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Errorf("%s: automountServiceAccountToken must be explicitly false", name)
	}

	// Pod-level: no host namespaces.
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		t.Errorf("%s: host namespaces must not be enabled", name)
	}

	// Pod-level security context.
	psc := pod.Spec.SecurityContext
	if psc == nil {
		t.Errorf("%s: pod SecurityContext must not be nil", name)
		return
	}
	if psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot {
		t.Errorf("%s: RunAsNonRoot must be true", name)
	}
	if psc.RunAsUser == nil || *psc.RunAsUser != 1001 {
		t.Errorf("%s: RunAsUser must be 1001, got %v", name, psc.RunAsUser)
	}
	if psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("%s: SeccompProfile.Type must be RuntimeDefault", name)
	}

	// Per-container security context.
	for _, c := range pod.Spec.Containers {
		sc := c.SecurityContext
		if sc == nil {
			t.Errorf("%s container %s: SecurityContext must not be nil", name, c.Name)
			continue
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Errorf("%s container %s: AllowPrivilegeEscalation must be false", name, c.Name)
		}
		if sc.Privileged != nil && *sc.Privileged {
			t.Errorf("%s container %s: Privileged must not be true", name, c.Name)
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Errorf("%s container %s: ReadOnlyRootFilesystem must be true", name, c.Name)
		}
		if sc.Capabilities == nil {
			t.Errorf("%s container %s: Capabilities must be set", name, c.Name)
		} else {
			hasDropAll := false
			for _, cap := range sc.Capabilities.Drop {
				if cap == "ALL" {
					hasDropAll = true
				}
			}
			if !hasDropAll {
				t.Errorf("%s container %s: must drop ALL capabilities", name, c.Name)
			}
		}
	}
}

func containerEnvMap(c corev1.Container) map[string]string {
	m := make(map[string]string, len(c.Env))
	for _, e := range c.Env {
		m[e.Name] = e.Value
	}
	return m
}

func hasServicePort(svc *corev1.Service, port int32) bool {
	for _, p := range svc.Spec.Ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func networkPolicyHasPort(rules []networkingv1.NetworkPolicyEgressRule, port int32) bool {
	target := intstr.FromInt32(port)
	for _, rule := range rules {
		for _, p := range rule.Ports {
			if p.Port != nil && *p.Port == target {
				return true
			}
		}
	}
	return false
}
