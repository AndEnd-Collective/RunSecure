package orchestrator

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
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
		CandidateJobs: assignedCandidate(),
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
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Equal(t, int64(1), d.st.Snapshot().AssignmentsTotal)
}

func TestLifecycleFastCompletedJobWaitsForLaggingJobEvidence(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.jobStatus = "queued"
	fake.jobRunnerID = 0
	fake.jobRunnerName = ""
	fake.jobChangeAfter = 2
	fake.jobStatusAfter = "completed"
	fake.jobRunnerIDAfter = fake.jitOnRunnerID
	fake.jobRunnerNameAfter = "runner"
	fake.mu.Unlock()
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 50 * time.Millisecond, AssignmentTimeout: 100 * time.Millisecond,
		PollInterval: 5 * time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "lagging-fast-complete",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	require.GreaterOrEqual(t, fake.jobGetCalled, 2)
	fake.mu.Unlock()
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
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
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_online_timeout"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerExitedUnassigned)
	require.Zero(t, d.st.Snapshot().UnassignedExitsTotal)
}

func TestFindAssignedJob_BatchesLargeBacklogByWorkflowRun(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobRunnerID = 99
	fake.jobRunnerName = "different-runner"
	fake.recentRunID = 6001
	fake.recentJobRunnerID = fake.jitOnRunnerID
	fake.recentJobName = "runner"
	fake.recentJobStatus = "in_progress"
	fake.mu.Unlock()
	candidates := make([]github.WorkflowJob, defaultJobCorrelationMaxCalls+1)
	for i := range candidates {
		candidates[i] = github.WorkflowJob{ID: int64(i + 1), RunID: 6001}
	}

	job, matched, err := NewSpawnWorker(d).findAssignedJob(
		context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", CandidateJobs: candidates,
		}, "runner", fake.jitOnRunnerID, d.clk.Now().Add(-time.Hour),
	)

	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, fake.recentJobID, job.ID)
	fake.mu.Lock()
	require.Equal(t, 1, fake.jobGetCalled,
		"only the rotated primary candidate should use the per-job endpoint")
	fake.mu.Unlock()
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
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_online_timeout"`)
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
		CandidateJobs: assignedCandidate(),
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
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	getCalls := fake.runnerGetCalled
	fake.mu.Unlock()
	require.Equal(t, 2, getCalls)
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventJobAssigned)
}

func TestLifecycleBusyCorrelationUsesAssignmentDeadline(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerChangeAfter = 2
	fake.runnerStatusAfter = "online"
	fake.runnerBusyAfter = true
	fake.jobResponseDelay = 10 * time.Millisecond
	fake.mu.Unlock()
	d.be.waitDelay = 20 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 5 * time.Millisecond, AssignmentTimeout: 50 * time.Millisecond,
		PollInterval: 100 * time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "assignment-deadline-context",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventJobAssigned)
}

func TestLifecycleRetriesTransientBusyCorrelationFailure(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobErrCode = http.StatusInternalServerError
	fake.jobErrUntil = 1
	fake.mu.Unlock()
	d.be.waitDelay = 20 * time.Millisecond
	d.lifecycle.PollInterval = time.Millisecond

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "transient-correlation",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	require.GreaterOrEqual(t, fake.jobGetCalled, 2)
	fake.mu.Unlock()
	require.NotContains(t,
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError, runnerOperationGetJob)
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestLifecycleBusyCorrelationAuthFailureDoesNotInterruptJob(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobErrCode = http.StatusForbidden
	fake.mu.Unlock()
	d.be.waitDelay = 30 * time.Millisecond
	d.lifecycle.AssignmentTimeout = 20 * time.Millisecond
	started := time.Now()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "busy-correlation-auth",
		CandidateJobs: assignedCandidate(),
	})

	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.GreaterOrEqual(t, time.Since(started), d.be.waitDelay,
		"a known-busy runner must be allowed to exit before correlation failure returns")
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_job_correlation_failed"`)
	d.requireEmitted(t, cornerstone.EventRunnerCompleted)
}

func TestLifecycleBusyRunnerObservationAuthFailureDoesNotInterruptJob(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobStatus = "queued"
	fake.jobRunnerID = 0
	fake.jobRunnerName = ""
	fake.jobChangeAfter = 2
	fake.jobStatusAfter = "completed"
	fake.jobRunnerIDAfter = fake.jitOnRunnerID
	fake.jobRunnerNameAfter = "runner"
	fake.runnerErrCode = http.StatusForbidden
	fake.runnerErrAfter = 2
	fake.runnerErrUntil = 2
	fake.mu.Unlock()
	d.be.waitDelay = 30 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 100 * time.Millisecond, AssignmentTimeout: 100 * time.Millisecond,
		PollInterval: time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "busy-runner-auth",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	require.GreaterOrEqual(t, fake.runnerGetCalled, 3)
	fake.mu.Unlock()
	require.NotContains(t,
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError, runnerOperationGetRunner)
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestLifecycleBusyRunnerRateLimitPausesWithoutInterruptingJob(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobStatus = "queued"
	fake.jobRunnerID = 0
	fake.jobRunnerName = ""
	fake.jobChangeAfter = 2
	fake.jobStatusAfter = "completed"
	fake.jobRunnerIDAfter = fake.jitOnRunnerID
	fake.jobRunnerNameAfter = "runner"
	fake.runnerErrCode = http.StatusTooManyRequests
	fake.runnerErrAfter = 2
	fake.runnerErrUntil = 2
	fake.mu.Unlock()
	d.be.waitDelay = 30 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 100 * time.Millisecond, AssignmentTimeout: 100 * time.Millisecond,
		PollInterval: time.Millisecond,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "busy-runner-rate-limit",
			CandidateJobs: assignedCandidate(),
		})
	}()
	require.Eventually(t, d.ratePaused.Load, 20*time.Millisecond, time.Millisecond,
		"rate-limit pause must be visible while the assigned runner is still active")

	require.NoError(t, <-errCh)
	d.requireEmitted(t, cornerstone.EventRatelimitPaused, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestLifecycleBusyCorrelationRecoversAfterOriginalAssignmentDeadline(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobErrCode = http.StatusInternalServerError
	fake.jobErrUntil = 1
	fake.mu.Unlock()
	d.be.waitDelay = 30 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 50 * time.Millisecond, AssignmentTimeout: 5 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "busy-correlation-after-deadline",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	require.GreaterOrEqual(t, fake.runnerGetCalled, 2,
		"a known-busy runner must remain observable after the original assignment deadline")
	fake.mu.Unlock()
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestLifecycleBusyFastExitRetriesCorrelationAfterAssignmentDeadline(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jobStatus = "queued"
	fake.jobRunnerID = 0
	fake.jobRunnerName = ""
	fake.jobChangeAfter = 3
	fake.jobStatusAfter = "completed"
	fake.jobRunnerIDAfter = fake.jitOnRunnerID
	fake.jobRunnerNameAfter = "runner"
	fake.mu.Unlock()
	d.be.waitDelay = 7 * time.Millisecond
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 50 * time.Millisecond, AssignmentTimeout: 5 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
	}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "busy-fast-exit-correlation-lag",
		CandidateJobs: assignedCandidate(),
	})

	require.NoError(t, err)
	fake.mu.Lock()
	require.GreaterOrEqual(t, fake.jobGetCalled, 3,
		"post-exit correlation must retry eventual-consistency lag")
	fake.mu.Unlock()
	d.requireEmitted(t, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestLifecycleCorrelatedAssignmentRequiresReservation(t *testing.T) {
	t.Run("busy observation", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh

		result := NewSpawnWorker(d).waitForLifecycle(
			context.Background(), SpawnIntent{
				Scope: "s", Repo: "o/r", SpawnID: "missing-busy-reservation",
				CandidateJobs: assignedCandidate(),
			}, "runner", fake.jitOnRunnerID,
			backend.Handle{SpawnID: "missing-busy-reservation", Backend: "fake"}, time.Minute,
		)

		require.ErrorContains(t, result.err, "state rejected correlated job")
		require.Equal(t, "github_job_correlation_failed", result.failureReason)
	})

	t.Run("post-exit correlation", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.runnerErrCode = http.StatusNotFound
		fake.jobStatus = "completed"
		fake.mu.Unlock()

		result := NewSpawnWorker(d).waitForLifecycle(
			context.Background(), SpawnIntent{
				Scope: "s", Repo: "o/r", SpawnID: "missing-exit-reservation",
				CandidateJobs: assignedCandidate(),
			}, "runner", fake.jitOnRunnerID,
			backend.Handle{SpawnID: "missing-exit-reservation", Backend: "fake"}, time.Minute,
		)

		require.ErrorContains(t, result.err, "state rejected correlated job")
		require.Equal(t, "github_job_correlation_failed", result.failureReason)
	})
}

func TestFindAssignedJobRejectsInvalidJobIDs(t *testing.T) {
	t.Run("exact candidate", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, _ := newFakeGitHubClient(t)
		d.gh = gh

		_, matched, err := NewSpawnWorker(d).findAssignedJob(
			context.Background(), SpawnIntent{
				Scope: "s", Repo: "o/r", CandidateJobs: []github.WorkflowJob{{ID: 0}},
			}, "runner", 100, d.clk.Now().Add(-time.Hour),
		)

		require.False(t, matched)
		require.ErrorContains(t, err, "invalid job id")
	})

	t.Run("recent search", func(t *testing.T) {
		d := newSpawnDeps(t)
		gh, fake := newFakeGitHubClient(t)
		d.gh = gh
		fake.mu.Lock()
		fake.recentRunID = 7001
		fake.recentRunCount = 1
		fake.recentJobID = 0
		fake.recentJobRunnerID = fake.jitOnRunnerID
		fake.recentJobName = "runner"
		fake.recentJobStatus = "in_progress"
		fake.mu.Unlock()

		_, matched, err := NewSpawnWorker(d).findAssignedJob(
			context.Background(), SpawnIntent{Scope: "s", Repo: "o/r"},
			"runner", fake.jitOnRunnerID, d.clk.Now().Add(-time.Hour),
		)

		require.False(t, matched)
		require.ErrorContains(t, err, "invalid job id")
	})
}

func TestFinalObservationLeadCapsAtOneSecond(t *testing.T) {
	require.Equal(t, time.Second, finalObservationLead(10*time.Second))
}

func TestPostBusyCorrelationGraceAllowsTwoPolls(t *testing.T) {
	timing := LifecycleTiming{AssignmentTimeout: 5 * time.Millisecond, PollInterval: 10 * time.Millisecond}
	require.Equal(t, 30*time.Millisecond, postBusyCorrelationGrace(timing))
}

func TestMarkCorrelatedAssignmentRejectsInvalidJobID(t *testing.T) {
	d := newSpawnDeps(t)
	err := NewSpawnWorker(d).markCorrelatedAssignment(
		SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "invalid-job"},
		"runner", 42, 0,
	)
	require.ErrorContains(t, err, "positive GitHub job id")
}

func TestWaitForAssignedJobEvidenceHonorsCancellation(t *testing.T) {
	d := newSpawnDeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, found, err := NewSpawnWorker(d).waitForAssignedJobEvidence(
		ctx, SpawnIntent{Scope: "s", Repo: "o/r"}, "runner", 42,
		d.clk.Now().Add(-time.Hour), time.Now().Add(time.Second), time.Second,
	)

	require.False(t, found)
	require.ErrorIs(t, err, context.Canceled)
}

func TestLifecycleOnlineDeadlineFinalObservationAuthFailure(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerErrCode = http.StatusForbidden
	fake.runnerErrAfter = 2
	fake.mu.Unlock()
	d.be.waitDelay = 2 * time.Second
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 5 * time.Millisecond, AssignmentTimeout: 200 * time.Millisecond,
		PollInterval: 200 * time.Millisecond,
	}

	result := NewSpawnWorker(d).waitForLifecycle(
		context.Background(),
		SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "online-deadline-auth-failure"},
		"rs-online-deadline-auth-failure",
		fake.jitOnRunnerID,
		backend.Handle{SpawnID: "online-deadline-auth-failure", Backend: "fake"},
		time.Minute,
	)

	require.ErrorIs(t, result.err, github.ErrAuthFailed)
	require.Equal(t, "github_runner_observation_failed", result.failureReason)
}

func TestLifecycleAssignmentDeadlineFinalObservationRateLimit(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "online"
	fake.runnerBusy = false
	fake.runnerErrCode = http.StatusTooManyRequests
	fake.runnerErrAfter = 2
	fake.mu.Unlock()
	d.be.waitDelay = 2 * time.Second
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 200 * time.Millisecond, AssignmentTimeout: 5 * time.Millisecond,
		PollInterval: 200 * time.Millisecond,
	}

	result := NewSpawnWorker(d).waitForLifecycle(
		context.Background(),
		SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "assignment-deadline-rate-limit"},
		"rs-assignment-deadline-rate-limit",
		fake.jitOnRunnerID,
		backend.Handle{SpawnID: "assignment-deadline-rate-limit", Backend: "fake"},
		time.Minute,
	)

	require.ErrorIs(t, result.err, github.ErrRateLimited)
	require.Equal(t, "github_runner_observation_rate_limited", result.failureReason)
}

func TestLifecycleOnlineDeadlineBoundsBlockedGitHubObservation(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerBlock = true
	fake.mu.Unlock()
	d.be.waitDelay = 2 * time.Second
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 25 * time.Millisecond, AssignmentTimeout: 200 * time.Millisecond,
		PollInterval: 200 * time.Millisecond,
	}
	started := time.Now()

	result := NewSpawnWorker(d).waitForLifecycle(
		context.Background(),
		SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "blocked-observation"},
		"rs-blocked-observation",
		fake.jitOnRunnerID,
		backend.Handle{SpawnID: "blocked-observation", Backend: "fake"},
		time.Minute,
	)

	require.Equal(t, "runner_online_timeout", result.failureReason)
	require.Less(t, time.Since(started), 150*time.Millisecond,
		"a blocked GitHub request must not extend the online deadline")
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
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_online_timeout"`)
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
		_, matched, err := NewSpawnWorker(d).findAssignedJob(
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
		_, matched, err := NewSpawnWorker(d).findAssignedJob(
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
		_, matched, err := NewSpawnWorker(d).findAssignedJob(
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
		_, matched, err := NewSpawnWorker(d).findAssignedJob(
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
		_, matched, err := NewSpawnWorker(d).findAssignedJob(
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
