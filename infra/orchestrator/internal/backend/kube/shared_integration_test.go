package kube_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
)

// TestSharedControllerLive is invoked by the existing kind/Calico harness.
// It uses the real backend, API, chart RBAC and generated policies. Only the
// container image and command are replaced with network probes: this test
// establishes lifecycle/isolation, not GitHub JIT delivery.
func TestSharedControllerLive(t *testing.T) {
	path := os.Getenv("RUNSECURE_TEST_KUBECONFIG")
	if path == "" {
		t.Skip("requires the kind/Calico integration harness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	require.NoError(t, err)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:runsecure-shared:rs-shared-runsecure-orchestrator"}
	cs, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	projects := map[string]string{"owner/alpha": "rs-shared-alpha", "owner/beta": "rs-shared-beta"}
	b, err := backendkube.NewForProjects(kube.NewClient(liveProbeClient{Interface: cs}), "shared", projects)
	require.NoError(t, err)

	// Negative control is an actual forbidden API operation, not only can-i.
	_, err = cs.CoreV1().Secrets("rs-shared-unenrolled").Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "must-not-exist"}}, metav1.CreateOptions{})
	require.True(t, k8serrors.IsForbidden(err), "controller must have no authority in an unenrolled namespace: %v", err)

	handles := make([]backend.Handle, 0, 2)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		for _, h := range handles {
			require.NoError(t, b.Teardown(cleanupCtx, h, true))
		}
	})
	for i, repo := range []string{"owner/alpha", "owner/beta"} {
		in := testInput(t, fmt.Sprintf("live-shared-%d", i))
		in.Scope, in.Repo = "shared", repo
		in.ResourcesMemory, in.ResourcesNanoCPUs = 64<<20, 50_000_000
		in.TCPEgressPorts = nil
		h, spawnErr := b.Spawn(ctx, in)
		require.NoError(t, spawnErr)
		handles = append(handles, h)
		for _, name := range []string{h.Refs["runner_pod"], h.Refs["proxy_pod"]} {
			liveKubectl(t, path, "wait", "--for=condition=Ready", "pod/"+name, "-n", h.Refs["namespace"], "--timeout=120s")
			pod, getErr := cs.CoreV1().Pods(h.Refs["namespace"]).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, getErr)
			require.False(t, *pod.Spec.AutomountServiceAccountToken)
			for _, volume := range pod.Spec.Volumes {
				require.Nil(t, volume.Projected, "no service-account token projection")
				if volume.Secret != nil {
					require.Equal(t, h.Refs["secret"], volume.Secret.SecretName, "only this spawn's secret may be mounted")
				}
			}
		}
	}
	// Reconstructing the backend must recover both projects using the same
	// namespace-scoped service account, without a cluster-wide list privilege.
	restarted, err := backendkube.NewForProjects(kube.NewClient(cs), "shared", projects)
	require.NoError(t, err)
	recovered, err := restarted.Reconcile(ctx, "shared")
	require.NoError(t, err)
	require.Len(t, recovered, 2)
	for _, h := range handles {
		ns := h.Refs["namespace"]
		proxy := fmt.Sprintf("rs-proxy-svc-%s.%s.svc", h.SpawnID, ns)
		liveKubectl(t, path, "exec", "-n", ns, h.Refs["runner_pod"], "-c", "runner", "--", "nc", "-z", "-w", "5", proxy, "3128")
		liveKubectl(t, path, "exec", "-n", ns, h.Refs["runner_pod"], "-c", "runner", "--", "sh", "-c", "test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token; test ! -e /run/secrets/runsecure-app-key/private-key")
	}
	// A positive own-proxy control is checked immediately before the denials.
	// Calico must enforce both egress and ingress across project namespaces.
	a, z := handles[0], handles[1]
	otherProxy := fmt.Sprintf("rs-proxy-svc-%s.%s.svc", z.SpawnID, z.Refs["namespace"])
	for _, target := range []struct{ host, port string }{{otherProxy, "3128"}, {"kubernetes.default.svc", "443"}, {"169.254.169.254", "80"}, {"1.1.1.1", "80"}} {
		args := []string{"exec", "-n", a.Refs["namespace"], a.Refs["runner_pod"], "-c", "runner", "--", "nc", "-z", "-w", "3", target.host, target.port}
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", path}, args...)...)
		out, denyErr := cmd.CombinedOutput()
		require.Error(t, denyErr, "unexpected network access to %s:%s: %s", target.host, target.port, out)
		require.NotContains(t, string(out), "not found", "a missing probe is not a network denial")
	}

	// Deleting one project's spawn must leave the other intact, then both
	// namespaces must return to zero job pods after the recovered teardown.
	for i, h := range recovered {
		require.NoError(t, restarted.Teardown(ctx, h, true))
		pods, listErr := cs.CoreV1().Pods(h.Refs["namespace"]).List(ctx, metav1.ListOptions{})
		require.NoError(t, listErr)
		require.Empty(t, pods.Items, "idle namespace must contain zero job pods")
		if i == 0 {
			other, otherErr := cs.CoreV1().Pods(recovered[1].Refs["namespace"]).List(ctx, metav1.ListOptions{})
			require.NoError(t, otherErr)
			require.Len(t, other.Items, 2, "one project's cleanup must preserve the other")
		}
	}
	handles = nil
}

func liveKubectl(t *testing.T, path string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", path}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", strings.Join(args, " "), out)
	return string(out)
}

// The API adapter changes executable payload only, retaining the generated
// placement, resources, security, Secret projections and NetworkPolicies.
type liveProbeClient struct{ kubernetes.Interface }

func (c liveProbeClient) CoreV1() typedcore.CoreV1Interface {
	return liveProbeCore{CoreV1Interface: c.Interface.CoreV1()}
}

type liveProbeCore struct{ typedcore.CoreV1Interface }

func (c liveProbeCore) Pods(ns string) typedcore.PodInterface {
	return liveProbePods{PodInterface: c.CoreV1Interface.Pods(ns)}
}

type liveProbePods struct{ typedcore.PodInterface }

func (p liveProbePods) Create(ctx context.Context, pod *corev1.Pod, options metav1.CreateOptions) (*corev1.Pod, error) {
	probe := pod.DeepCopy()
	c := &probe.Spec.Containers[0]
	c.ImagePullPolicy = corev1.PullIfNotPresent
	if pod.Labels[kube.LabelRole] == kube.RoleRunner {
		c.Image, c.Command = "nicolaka/netshoot:v0.13", []string{"sleep", "600"}
	} else {
		c.Image = "busybox:1.37.0"
		c.Command = []string{"sh", "-c", "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK' | nc -l -p 3128; done"}
	}
	c.Args = nil
	return p.PodInterface.Create(ctx, probe, options)
}
