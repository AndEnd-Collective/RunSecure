package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	backendkube "github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend/kube"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/kube"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type startupFakeBackend struct {
	name         string
	handles      []backend.Handle
	reconcileErr error
	teardownErr  error
	tornDown     []string
}

func (f *startupFakeBackend) Name() string { return f.name }

func (f *startupFakeBackend) Spawn(context.Context, backend.SpawnInput) (backend.Handle, error) {
	return backend.Handle{}, nil
}

func (f *startupFakeBackend) WaitForExit(context.Context, backend.Handle, time.Duration) (int, bool) {
	return 0, false
}

func (f *startupFakeBackend) Teardown(_ context.Context, handle backend.Handle, _ bool) error {
	f.tornDown = append(f.tornDown, handle.SpawnID)
	return f.teardownErr
}

func (f *startupFakeBackend) Reconcile(context.Context, string) ([]backend.Handle, error) {
	return append([]backend.Handle(nil), f.handles...), f.reconcileErr
}

func kubeHandle(spawnID string) backend.Handle {
	return backend.Handle{
		SpawnID: spawnID,
		Backend: "kube",
		Refs: map[string]string{
			"namespace":  "runsecure-scope",
			"secret":     "rs-secret-" + spawnID,
			"runner_pod": "rs-runner-" + spawnID,
			"repo_label": "owner_repo",
		},
	}
}

func TestCleanupRecoveredKubeSpawnsRegistrationThenSecret(t *testing.T) {
	be := &startupFakeBackend{
		name: "kube", handles: []backend.Handle{kubeHandle("b"), kubeHandle("a")},
	}
	gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{
		"owner/repo": {
			ownedRecoveredRunner(43, "rs-b-runner", "scope"),
			ownedRecoveredRunner(42, "rs-a-runner", "scope"),
		},
	}}

	require.NoError(t, cleanupRecoveredKubeSpawns(
		context.Background(), "scope", []string{"owner/repo"}, be, gh,
	))
	require.Equal(t, []int64{42, 43}, gh.deletedIDs)
	require.Equal(t, []string{"a", "b"}, be.tornDown)
}

func TestCleanupRecoveredKubeSpawnsNoPodsStillDeletesRegistrationDebt(t *testing.T) {
	be := &startupFakeBackend{name: "kube"}
	gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{
		"owner/repo": {ownedRecoveredRunner(42, "rs-registration-only-runner", "scope")},
	}}

	require.NoError(t, cleanupRecoveredKubeSpawns(
		context.Background(), "scope", []string{"owner/repo"}, be, gh,
	))
	require.Equal(t, []int64{42}, gh.deletedIDs)
	require.Empty(t, be.tornDown)
}

func TestCleanupRecoveredKubeSpawnsFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*startupFakeBackend, *fakeColdStartGitHub)
		wantErr string
	}{
		{
			name: "reconcile",
			mutate: func(be *startupFakeBackend, _ *fakeColdStartGitHub) {
				be.reconcileErr = errors.New("api denied")
			},
			wantErr: "reconcile recovered",
		},
		{
			name: "invalid handle",
			mutate: func(be *startupFakeBackend, _ *fakeColdStartGitHub) {
				be.handles[0].Refs["namespace"] = "other"
			},
			wantErr: "invalid ownership",
		},
		{
			name: "runner list",
			mutate: func(_ *startupFakeBackend, gh *fakeColdStartGitHub) {
				gh.listErr = errors.New("github denied")
			},
			wantErr: "list runners",
		},
		{
			name: "runner delete",
			mutate: func(_ *startupFakeBackend, gh *fakeColdStartGitHub) {
				gh.deleteErr = errors.New("delete denied")
			},
			wantErr: "delete runner",
		},
		{
			name: "secret teardown",
			mutate: func(be *startupFakeBackend, _ *fakeColdStartGitHub) {
				be.teardownErr = errors.New("secret denied")
			},
			wantErr: "teardown recovered",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be := &startupFakeBackend{name: "kube", handles: []backend.Handle{kubeHandle("a")}}
			gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{
				"owner/repo": {ownedRecoveredRunner(42, "rs-a-runner", "scope")},
			}}
			tc.mutate(be, gh)

			err := cleanupRecoveredKubeSpawns(
				context.Background(), "scope", []string{"owner/repo"}, be, gh,
			)
			require.ErrorContains(t, err, tc.wantErr)
			if tc.name != "secret teardown" {
				require.Empty(t, be.tornDown)
			}
		})
	}
}

func TestValidateRecoveredKubeHandlesRejectsDuplicateAndMalformed(t *testing.T) {
	valid := kubeHandle("a")
	for _, handles := range [][]backend.Handle{
		{valid, valid},
		{{Backend: "compose", SpawnID: "a", Refs: valid.Refs}},
		{{Backend: "kube", SpawnID: "", Refs: valid.Refs}},
		{{Backend: "kube", SpawnID: "a", Refs: map[string]string{
			"namespace": "runsecure-scope", "secret": "wrong", "runner_pod": "rs-runner-a",
			"repo_label": "owner_repo",
		}}},
		{{Backend: "kube", SpawnID: "a", Refs: map[string]string{
			"namespace": "runsecure-scope", "secret": "rs-secret-a", "runner_pod": "rs-runner-a",
			"repo_label": "other_repo",
		}}},
	} {
		_, err := validateRecoveredKubeHandles("scope", []string{"owner/repo"}, handles)
		require.ErrorContains(t, err, "invalid ownership")
	}
}

func TestCleanupRecoveredKubeProjectsWithRealBackend(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	mapping := map[string]string{"owner/one": "project-one", "owner/two": "project-two"}
	for i, repo := range []string{"owner/one", "owner/two"} {
		in := backend.SpawnInput{Scope: "scope", Repo: repo, Namespace: mapping[repo], SpawnID: []string{"one", "two"}[i]}
		secret := kube.SpawnSecret(in, nil, nil, nil)
		_, err := cs.CoreV1().Secrets(mapping[repo]).Create(ctx, secret, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	be, err := backendkube.NewForProjects(kube.NewClient(cs), "scope", mapping)
	require.NoError(t, err)
	gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{
		"owner/one": {ownedRecoveredRunner(1, "rs-one-runner", "scope")},
		"owner/two": {ownedRecoveredRunner(2, "rs-two-runner", "scope")},
	}}
	cs.ClearActions()
	require.NoError(t, cleanupRecoveredKubeSpawnsForProjects(ctx, "scope", mapping, be, gh))
	require.Equal(t, []int64{1, 2}, gh.deletedIDs)
	for _, action := range cs.Actions() {
		require.Contains(t, []string{"project-one", "project-two"}, action.GetNamespace())
	}
	handles, err := be.Reconcile(ctx, "scope")
	require.NoError(t, err)
	require.Empty(t, handles)
}

func TestValidateRecoveredKubeProjectsRejectsForgedIdentity(t *testing.T) {
	mapping := map[string]string{"owner/one": "project-one", "owner/two": "project-two"}
	for _, key := range []string{"scope", "repo", "repo_label", "namespace", "secret", "runner_pod"} {
		t.Run(key, func(t *testing.T) {
			h := backend.Handle{Backend: "kube", SpawnID: "one", Refs: map[string]string{
				"scope": "scope", "repo": "owner/one", "namespace": "project-one", "repo_label": "owner_one",
				"secret": "rs-secret-one", "runner_pod": "rs-runner-one",
			}}
			h.Refs[key] = "forged"
			be := &startupFakeBackend{name: "kube", handles: []backend.Handle{h}}
			gh := &fakeColdStartGitHub{}
			require.ErrorContains(t, cleanupRecoveredKubeSpawnsForProjects(context.Background(), "scope", mapping, be, gh), "invalid ownership")
			require.Empty(t, be.tornDown)
			require.Empty(t, gh.deletedIDs)
		})
	}
}
