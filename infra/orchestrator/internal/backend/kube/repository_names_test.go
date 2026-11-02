package kube_test

import (
	"context"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestSharedProjectsRouteLeadingPunctuationRepositories(t *testing.T) {
	for _, name := range []string{".github", ".Release", ".Security", "_tools", "-tools"} {
		t.Run(name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			repo := "owner/" + name
			b, err := backendkube.NewForProjects(kube.NewClient(cs), "controller", map[string]string{repo: "project-dot"})
			require.NoError(t, err)
			in := testInput(t, "dot-repo")
			in.Scope, in.Repo = "controller", repo
			h, err := b.Spawn(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, "project-dot", h.Refs["namespace"])
			pods, err := cs.CoreV1().Pods("project-dot").List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, pods.Items, 2)
		})
	}
	for _, name := range []string{".", "..", "../escape", "nested/repository", "%2egithub"} {
		cs := fake.NewSimpleClientset()
		_, err := backendkube.NewForProjects(kube.NewClient(cs), "controller", map[string]string{"owner/" + name: "project-dot"})
		require.Error(t, err)
		require.Empty(t, cs.Actions())
	}
}
