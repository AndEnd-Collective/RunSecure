package orchestrator

import (
	"context"
	"fmt"
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

func TestLifecycleFastCompletedJobUsesPostExitJobCorrelation(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	// The JIT registration has already disappeared by both runner samples,
	// but the completed job retains exact runner_id evidence.
	fake.runnerErrCode = http.StatusNotFound
	fake.jobRunnerID = fake.jitOnRunnerID
	fake.jobRunnerName = "rs-fast-complete-runner"
	fake.jobStatus = "completed"
	fake.jobConclusion = "success"
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second
	started := time.Now()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "fast-complete",
		CandidateJobs: []github.WorkflowJob{{ID: 9001, RunID: 7001}},
	})

	require.NoError(t, err)
	require.Less(t, time.Since(started), d.lifecycle.PollInterval,
		"correlation must not wait for the next runner polling interval")
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Equal(t, int64(1), d.st.Snapshot().AssignmentsTotal)
}

func TestLifecycleFastLaterDependentJobUsesCandidateRunCorrelation(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	// The exact job queued at poll time was not assigned. A downstream job in
	// that already-existing workflow run became eligible and completed before
	// the next two-second runner sample.
	fake.runnerErrCode = http.StatusNotFound
	fake.jobRunnerID = 99
	fake.jobRunnerName = "different-runner"
	fake.jobStatus = "completed"
	fake.recentRunID = 6001
	fake.recentJobRunnerID = fake.jitOnRunnerID
	fake.recentJobName = "rs-later-dependent-runner"
	fake.recentJobStatus = "completed"
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "later-dependent",
		CandidateJobs: []github.WorkflowJob{{ID: 9001, RunID: 6001}},
	})

	require.NoError(t, err)
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
}

func TestLifecycleRecentJobSearchBoundIsFailureNotUnassigned(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.recentRunID = 7000
	fake.recentRunCount = defaultJobCorrelationMaxRuns + 1
	fake.recentJobRunnerID = 99
	fake.recentJobName = "different-runner"
	fake.recentJobStatus = "completed"
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "bounded-correlation",
	})

	require.ErrorIs(t, err, github.ErrRecentJobSearchIndeterminate)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_job_correlation_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Zero(t, d.st.Snapshot().UnassignedExitsTotal)
}

func TestCorrelateCompletedJob_BoundsExactCandidateAPICalls(t *testing.T) {
	for _, count := range []int{defaultJobCorrelationMaxCalls, defaultJobCorrelationMaxCalls + 1} {
		t.Run(fmt.Sprintf("candidates_%d", count), func(t *testing.T) {
			d := newSpawnDeps(t)
			gh, _ := newFakeGitHubClient(t)
			d.gh = gh
			candidates := make([]github.WorkflowJob, count)
			for i := range candidates {
				candidates[i] = github.WorkflowJob{ID: int64(i + 1)}
			}

			matched, err := NewSpawnWorker(d).correlateCompletedJob(
				context.Background(), SpawnIntent{
					Scope: "s", Repo: "o/r", CandidateJobs: candidates,
				}, "runner", 42, d.clk.Now().Add(-time.Hour),
			)

			require.False(t, matched)
			require.ErrorIs(t, err, github.ErrRecentJobSearchIndeterminate)
		})
	}
}

func TestLifecycleRecentJobSearchRateLimitPreservesReadinessState(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.queueErrCode["o/r"] = http.StatusForbidden
	fake.rlAfterResponse = true
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "correlation-rate-limit",
	})

	require.ErrorIs(t, err, github.ErrRateLimited)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_job_correlation_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.True(t, d.ratePaused.Load())
	d.rlMu.Lock()
	require.Equal(t, 0, d.rateLimit.Remaining)
	require.Equal(t, 5000, d.rateLimit.Limit)
	d.rlMu.Unlock()
	require.Equal(t, "github_rate_limited",
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError[runnerOperationFindRecentJob].Class)
}

func TestLifecycleFastAssignmentUsesFinalRunnerObservation(t *testing.T) {
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
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "fast-final-observation",
	})

	require.NoError(t, err)
	fake.mu.Lock()
	getCalls := fake.runnerGetCalled
	fake.mu.Unlock()
	require.Equal(t, 2, getCalls)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
}

func TestLifecycleDeadlineMakesFinalRunnerObservation(t *testing.T) {
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
	d.lifecycle = LifecycleTiming{
		OnlineTimeout:     5 * time.Millisecond,
		AssignmentTimeout: 5 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "deadline-final-observation",
	})

	require.NoError(t, err)
	fake.mu.Lock()
	getCalls := fake.runnerGetCalled
	fake.mu.Unlock()
	require.Equal(t, 2, getCalls)
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventJobAssigned)
}

func TestLifecycleFinalRunnerObservationAuthFailureStopsClassification(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerErrCode = http.StatusForbidden
	fake.runnerErrAfter = 2
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "fast-final-auth-failure",
	})

	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_runner_observation_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
}

func TestLifecyclePostExitJobCorrelationAuthFailureStopsClassification(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.jobErrCode = http.StatusForbidden
	fake.mu.Unlock()
	d.lifecycle.PollInterval = 2 * time.Second

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "fast-job-auth-failure",
		CandidateJobs: []github.WorkflowJob{{ID: 9001}},
	})

	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_job_correlation_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
}

func TestCorrelateCompletedJob_FailsClosedAndAcceptsExactRunnerName(t *testing.T) {
	t.Run("missing candidate continues", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.jobErrCode = http.StatusNotFound
		fake.mu.Unlock()
		matched, err := NewSpawnWorker(d).correlateCompletedJob(
			context.Background(), SpawnIntent{
				Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 1}},
			}, "runner", 42, d.clk.Now().Add(-time.Hour),
		)
		require.NoError(t, err)
		require.False(t, matched)
	})

	t.Run("auth failure is propagated and classified", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.jobErrCode = http.StatusForbidden
		fake.mu.Unlock()
		matched, err := NewSpawnWorker(d).correlateCompletedJob(
			context.Background(), SpawnIntent{
				Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 1}},
			}, "runner", 42, d.clk.Now().Add(-time.Hour),
		)
		require.False(t, matched)
		require.ErrorIs(t, err, github.ErrAuthFailed)
		require.Equal(t, "github_auth_failed",
			d.st.Snapshot().PerRepo["o/r"].RunnerOperationError[runnerOperationGetJob].Class)
	})

	t.Run("mismatched runner is not evidence", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.jobRunnerID = 99
		fake.jobRunnerName = "different"
		fake.mu.Unlock()
		matched, err := NewSpawnWorker(d).correlateCompletedJob(
			context.Background(), SpawnIntent{
				Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 1}},
			}, "runner", 42, d.clk.Now().Add(-time.Hour),
		)
		require.NoError(t, err)
		require.False(t, matched)
	})

	t.Run("exact runner name proves assignment when id is unavailable", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.jobRunnerID = 0
		fake.jobRunnerName = "runner"
		fake.jobStatus = "completed"
		fake.mu.Unlock()
		matched, err := NewSpawnWorker(d).correlateCompletedJob(
			context.Background(), SpawnIntent{
				Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 1}},
			}, "runner", 42, d.clk.Now().Add(-time.Hour),
		)
		require.NoError(t, err)
		require.True(t, matched)
	})

	t.Run("queued job is not assignment evidence", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.jobRunnerID = 42
		fake.jobStatus = "queued"
		fake.mu.Unlock()
		matched, err := NewSpawnWorker(d).correlateCompletedJob(
			context.Background(), SpawnIntent{
				Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 1}},
			}, "runner", 42, d.clk.Now().Add(-time.Hour),
		)
		require.NoError(t, err)
		require.False(t, matched)
	})
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
