package main

import (
	"context"
	"errors"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/stretchr/testify/require"
)

type fakeColdStartDocker struct {
	containers []docker.Container
	listErr    error
	deleteErr  error
	deleted    []string
}

func (f *fakeColdStartDocker) ListContainersForScope(context.Context, string) ([]docker.Container, error) {
	return f.containers, f.listErr
}

func (f *fakeColdStartDocker) DeleteContainer(_ context.Context, id string, force bool) error {
	if !force {
		return errors.New("expected force cleanup")
	}
	f.deleted = append(f.deleted, id)
	return f.deleteErr
}

type fakeColdStartGitHub struct {
	runners     map[string][]github.Runner
	listErr     error
	deleteErr   error
	listedRepos []string
	deletedIDs  []int64
}

func (f *fakeColdStartGitHub) ListRunners(_ context.Context, repo string) ([]github.Runner, github.RateLimit, error) {
	f.listedRepos = append(f.listedRepos, repo)
	return f.runners[repo], github.RateLimit{}, f.listErr
}

func (f *fakeColdStartGitHub) DeleteRunner(_ context.Context, _ string, id int64) error {
	f.deletedIDs = append(f.deletedIDs, id)
	return f.deleteErr
}

func recoveredContainer(id, role, repo, spawnID string) docker.Container {
	name := "rs-" + spawnID + "-" + role
	return docker.Container{ID: id, Name: name, Labels: map[string]string{
		"runsecure.role": role, "runsecure.repo": repo, "runsecure.spawn_id": spawnID,
	}}
}

func TestCleanupRecoveredSpawns_RemovesExactRegistrationBeforeContainers(t *testing.T) {
	dc := &fakeColdStartDocker{containers: []docker.Container{
		recoveredContainer("proxy-b", "proxy", "owner/repo", "spawn-1"),
		recoveredContainer("runner-a", "runner", "owner/repo", "spawn-1"),
	}}
	gh := &fakeColdStartGitHub{runners: map[string][]github.Runner{
		"owner/repo": {
			{ID: 41, Name: "unrelated"},
			{ID: 42, Name: "rs-spawn-1-runner", Status: "online", Busy: true},
		},
	}}

	require.NoError(t, cleanupRecoveredSpawns(
		context.Background(), "scope", []string{"owner/repo"}, dc, gh,
	))
	require.Equal(t, []string{"owner/repo"}, gh.listedRepos)
	require.Equal(t, []int64{42}, gh.deletedIDs)
	require.Equal(t, []string{"proxy-b", "runner-a"}, dc.deleted)
}

func TestCleanupRecoveredSpawns_GitHubFailureLeavesContainersForRetry(t *testing.T) {
	dc := &fakeColdStartDocker{containers: []docker.Container{
		recoveredContainer("runner", "runner", "owner/repo", "spawn-1"),
	}}
	gh := &fakeColdStartGitHub{listErr: errors.New("github unavailable")}

	err := cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, gh)
	require.ErrorContains(t, err, "list runners")
	require.Empty(t, dc.deleted, "containers must remain until registrations can be reconciled")
}

func TestCleanupRecoveredSpawns_DeregistrationFailureLeavesContainersForRetry(t *testing.T) {
	dc := &fakeColdStartDocker{containers: []docker.Container{
		recoveredContainer("runner", "runner", "owner/repo", "spawn-1"),
	}}
	gh := &fakeColdStartGitHub{
		runners:   map[string][]github.Runner{"owner/repo": {{ID: 42, Name: "rs-spawn-1-runner"}}},
		deleteErr: errors.New("delete unavailable"),
	}

	err := cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, gh)
	require.ErrorContains(t, err, "delete runner 42")
	require.Empty(t, dc.deleted, "containers must remain until registrations can be deregistered")
}

func TestCleanupRecoveredSpawns_RejectsUnownedOrMalformedRunner(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container docker.Container
		want      string
	}{
		{name: "unexpected repo", container: recoveredContainer("runner", "runner", "other/repo", "spawn-1"), want: "invalid ownership"},
		{name: "missing spawn", container: recoveredContainer("runner", "runner", "owner/repo", ""), want: "invalid spawn"},
		{name: "name mismatch", container: docker.Container{ID: "runner", Name: "not-owned", Labels: map[string]string{
			"runsecure.role": "runner", "runsecure.repo": "owner/repo", "runsecure.spawn_id": "spawn-1",
		}}, want: "invalid ownership"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dc := &fakeColdStartDocker{containers: []docker.Container{tc.container}}
			gh := &fakeColdStartGitHub{}
			err := cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, gh)
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, gh.listedRepos)
			require.Empty(t, dc.deleted)
		})
	}
}

func TestCleanupRecoveredSpawns_PropagatesDockerErrors(t *testing.T) {
	dc := &fakeColdStartDocker{listErr: errors.New("socket denied")}
	err := cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, &fakeColdStartGitHub{})
	require.ErrorContains(t, err, "list recovered containers")

	dc = &fakeColdStartDocker{
		containers: []docker.Container{recoveredContainer("proxy", "proxy", "owner/repo", "spawn-1")},
		deleteErr:  errors.New("delete denied"),
	}
	err = cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, &fakeColdStartGitHub{})
	require.ErrorContains(t, err, "delete recovered container")
}

func TestCleanupRecoveredSpawns_NoContainersIsNoOp(t *testing.T) {
	dc := &fakeColdStartDocker{containers: []docker.Container{{
		ID: "control-plane", Name: "orchestrator", Labels: map[string]string{"runsecure.scope": "scope"},
	}}}
	gh := &fakeColdStartGitHub{listErr: errors.New("must not be called")}
	require.NoError(t, cleanupRecoveredSpawns(context.Background(), "scope", []string{"owner/repo"}, dc, gh))
	require.Empty(t, gh.listedRepos)
}
