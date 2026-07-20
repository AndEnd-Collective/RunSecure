package orchestrator

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/stretchr/testify/require"
)

func TestLifecycleStopsRunnerPollingAfterAssignment(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerChangeAfter = 2
	fake.runnerStatusAfter = "online"
	fake.runnerBusyAfter = true
	fake.mu.Unlock()
	d.be.waitDelay = 15 * time.Millisecond
	d.lifecycle.PollInterval = time.Millisecond

	require.NoError(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "assigned-no-more-polls",
	}))

	fake.mu.Lock()
	getCalls := fake.runnerGetCalled
	fake.mu.Unlock()
	require.Equal(t, 2, getCalls,
		"an assigned runner must not consume GitHub API calls while its backend is still running")
}

func TestLifecycleBackendTimeoutIsNotUnassignedExit(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "online"
	fake.runnerBusy = false
	fake.mu.Unlock()
	d.be.waitExitCode = -1
	d.be.waitTimedOut = true

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "backend-timeout",
	})
	require.ErrorContains(t, err, "spawn timed out")
	d.requireEmitted(t, cornerstone.EventSpawnTimeoutForcedTeardown)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Zero(t, d.st.Snapshot().UnassignedExitsTotal)
}

func TestLifecycleCancellationIsNotUnassignedExit(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.mu.Unlock()
	d.be.inspectExitDelay = 100 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: time.Second, AssignmentTimeout: time.Second,
		PollInterval: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() {
		errCh <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "cancel-not-unassigned",
		})
	}()
	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.runnerGetCalled > 0
	}, time.Second, time.Millisecond, "runner observation never started")
	cancel()
	err := <-errCh

	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_observation_cancelled"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Zero(t, d.st.Snapshot().UnassignedExitsTotal)
}

func TestLifecycleCancelledBackendExitPreemptsUnassignedClassification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, handled := lifecycleTransportResult(ctx, backendExit{exitCode: -1})
	require.True(t, handled)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Equal(t, "runner_observation_cancelled", result.failureReason)
	require.False(t, result.unassigned)
}

func TestLifecycleTransientObservationStillPollsBeforeAssignment(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.runnerErrAfter = 1
	fake.mu.Unlock()
	d.be.inspectExitDelay = 20 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 5 * time.Millisecond, AssignmentTimeout: 20 * time.Millisecond,
		PollInterval: time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "transient-observation",
	})
	require.ErrorContains(t, err, "did not become online")

	fake.mu.Lock()
	getCalls := fake.runnerGetCalled
	fake.mu.Unlock()
	require.Greater(t, getCalls, 1, "unassigned runners must continue lifecycle polling")
}

func TestLifecyclePollObservationFailureStopsDelivery(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerErrCode = http.StatusForbidden
	fake.runnerErrAfter = 2
	fake.mu.Unlock()
	d.be.waitDelay = 20 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 50 * time.Millisecond, AssignmentTimeout: 50 * time.Millisecond,
		PollInterval: time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "poll-observation-failure",
	})

	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_runner_observation_failed"`)
}
