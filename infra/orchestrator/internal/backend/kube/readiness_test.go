package kube_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	kubeclient "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"testing"
)

func TestReadinessIsBoundedAndRotatesAcrossAllProjects(t *testing.T) {
	cs := fake.NewSimpleClientset()
	projects := map[string]string{}
	for i := 0; i < 93; i++ {
		projects[fmt.Sprintf("owner/repo-%d", i)] = fmt.Sprintf("project-%03d", i)
	}
	b, err := kube.NewForProjects(kubeclient.NewClient(cs), "scope", projects)
	require.NoError(t, err)
	probe := b.(interface {
		Ready(context.Context, string) error
	})
	seen := map[string]bool{}
	for i := 0; i < 93; i++ {
		cs.ClearActions()
		require.NoError(t, probe.Ready(context.Background(), "scope"))
		require.Len(t, cs.Actions(), 4)
		ns := cs.Actions()[0].GetNamespace()
		for _, action := range cs.Actions() {
			require.Equal(t, ns, action.GetNamespace())
		}
		seen[ns] = true
	}
	require.Len(t, seen, 93)
	cs.ClearActions()
	require.Error(t, probe.Ready(context.Background(), "other-scope"))
	require.Empty(t, cs.Actions())
	cs.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("API unavailable")
	})
	require.ErrorContains(t, probe.Ready(context.Background(), "scope"), "API unavailable")
}
