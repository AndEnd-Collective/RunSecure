package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/stretchr/testify/require"
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
