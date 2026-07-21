package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
)

const (
	defaultRunnerOnlineTimeout     = 60 * time.Second
	defaultRunnerAssignmentTimeout = 120 * time.Second
	defaultRunnerPollInterval      = 2 * time.Second
	defaultCleanupRetryInterval    = time.Second
	defaultJobCorrelationLookback  = 7 * 24 * time.Hour
	defaultJobCorrelationMaxRuns   = 50
	defaultJobCorrelationMaxCalls  = 64
	defaultExactCandidateProbes    = 1
)

// DefaultLifecycleTiming is the production registration and assignment
// observation policy. Tests inject shorter values through SpawnDeps.
func DefaultLifecycleTiming() LifecycleTiming {
	return LifecycleTiming{
		OnlineTimeout:        defaultRunnerOnlineTimeout,
		AssignmentTimeout:    defaultRunnerAssignmentTimeout,
		PollInterval:         defaultRunnerPollInterval,
		CleanupRetryInterval: defaultCleanupRetryInterval,
	}
}

type backendExit struct {
	exitCode int
	timedOut bool
}

type lifecycleResult struct {
	exitCode      int
	timedOut      bool
	err           error
	delivered     bool
	unassigned    bool
	failureReason string
}

func (w *SpawnWorker) waitForLifecycle(
	ctx context.Context,
	intent SpawnIntent,
	containerName string,
	runnerID int64,
	h backend.Handle,
	wallTimeout time.Duration,
) lifecycleResult {
	timing := normalizedLifecycleTiming(w.deps.LifecycleTiming())
	startedAt := time.Now()
	onlineDeadlineAt := startedAt.Add(timing.OnlineTimeout)
	assignmentDeadlineAt := startedAt.Add(timing.AssignmentTimeout)
	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()

	exitCh := make(chan backendExit, 1)
	go func() {
		exitCode, timedOut := w.deps.Backend().WaitForExit(waitCtx, h, wallTimeout)
		exitCh <- backendExit{exitCode: exitCode, timedOut: timedOut}
	}()

	online := false
	assigned := false
	busyObserved := false
	lastObservationErr := error(nil)
	correlationSince := w.deps.Clock().Now().Add(-defaultJobCorrelationLookback)

	observe := func(observationCtx context.Context) lifecycleResult {
		runner, _, err := w.deps.GitHub().GetRunner(observationCtx, intent.Repo, runnerID)
		w.recordRunnerOperation(intent.Repo, runnerOperationGetRunner, err)
		if err != nil {
			lastObservationErr = err
			w.pauseForRateLimit(intent.Scope, err)
			if busyObserved {
				// Busy is durable delivery evidence. A later observation failure
				// must degrade readiness and pause scheduling when rate-limited,
				// but it must never tear down the active job.
				return lifecycleResult{}
			}
			if errors.Is(err, github.ErrAuthFailed) {
				return lifecycleFailure("github_runner_observation_failed", err)
			}
			if errors.Is(err, github.ErrRateLimited) {
				return lifecycleFailure("github_runner_observation_rate_limited", err)
			}
			return lifecycleResult{}
		}
		lastObservationErr = nil
		if runner.Status == "online" || runner.Busy {
			if !online {
				online = true
				if w.deps.State().MarkOnline(intent.SpawnID, w.deps.Clock().Now()) {
					_ = w.deps.Emit().EmitRunnerOnline(cornerstone.RunnerOnlineFields{
						Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
						ContainerName: containerName, GitHubRunnerID: runnerID,
					})
				}
			}
		}
		if runner.Busy && !assigned {
			busyObserved = true
			// Busy alone proves that some job was assigned, but not which one.
			// Resolve the exact Actions job before moving state from online to
			// assigned so scheduler coverage can atomically exchange generic
			// online capacity for a durable consumed-job tombstone.
			// Once Busy proves delivery, the absolute assignment deadline no
			// longer authorizes teardown. Give each instrumentation attempt a
			// fresh, bounded window so a long-running job can recover exact job
			// correlation after that original deadline has elapsed.
			correlationDeadline := time.Now().Add(timing.AssignmentTimeout)
			assignmentCtx, cancelAssignment := context.WithDeadline(observationCtx, correlationDeadline)
			job, correlated, correlationErr := w.findAssignedJob(
				assignmentCtx, intent, containerName, runnerID, correlationSince,
			)
			cancelAssignment()
			if correlationErr != nil {
				lastObservationErr = correlationErr
				w.pauseForRateLimit(intent.Scope, correlationErr)
				// Busy is direct evidence that GitHub delivered a job. Correlation
				// is instrumentation, so an API/permission/bound failure must not
				// tear down the active runner. Keep observing and expose the
				// operation error through readiness until the same call recovers.
				return lifecycleResult{}
			}
			lastObservationErr = nil
			if correlated {
				if markErr := w.markCorrelatedAssignment(intent, containerName, runnerID, job.ID); markErr != nil {
					return lifecycleFailure("github_job_correlation_failed", markErr)
				}
				assigned = true
			}
		}
		return lifecycleResult{}
	}

	observationDeadline := func() time.Time {
		if busyObserved {
			return time.Now().Add(timing.AssignmentTimeout)
		}
		if !online && onlineDeadlineAt.Before(assignmentDeadlineAt) {
			return onlineDeadlineAt
		}
		return assignmentDeadlineAt
	}
	observeBeforeDeadline := func() lifecycleResult {
		observationCtx, cancel := context.WithDeadline(ctx, observationDeadline())
		defer cancel()
		return observe(observationCtx)
	}

	// Start absolute lifecycle deadlines before the first GitHub observation.
	// Every observation is itself bounded by the active deadline, so a stalled
	// HTTP request cannot extend the 60/120-second delivery contract.
	onlineTimer := time.NewTimer(time.Until(onlineDeadlineAt))
	defer stopTimer(onlineTimer)
	assignmentTimer := time.NewTimer(time.Until(assignmentDeadlineAt))
	defer stopTimer(assignmentTimer)
	onlineFinalTimer := time.NewTimer(time.Until(onlineDeadlineAt.Add(-finalObservationLead(timing.OnlineTimeout))))
	defer stopTimer(onlineFinalTimer)
	assignmentFinalTimer := time.NewTimer(time.Until(assignmentDeadlineAt.Add(-finalObservationLead(timing.AssignmentTimeout))))
	defer stopTimer(assignmentFinalTimer)
	onlineFinalC := onlineFinalTimer.C
	assignmentFinalC := assignmentFinalTimer.C

	if failure := observeBeforeDeadline(); failure.err != nil {
		return failure
	}

	poll := time.NewTicker(timing.PollInterval)
	defer poll.Stop()
	pollC := poll.C
	if online {
		stopTimer(onlineTimer)
		stopTimer(onlineFinalTimer)
		onlineFinalC = nil
	}
	if busyObserved {
		stopTimer(assignmentTimer)
		stopTimer(assignmentFinalTimer)
		assignmentFinalC = nil
	}
	if assigned {
		poll.Stop()
		pollC = nil
	}

	for {
		select {
		case <-ctx.Done():
			return lifecycleFailure("runner_observation_cancelled", ctx.Err())
		case result := <-exitCh:
			// Backend wall-clock expiry and worker cancellation are transport
			// outcomes, not evidence that a healthy runner exited without a job.
			// Preserve them for Execute's timeout/cancellation handling before
			// considering the unassigned-runner failure below.
			if transportResult, ok := lifecycleTransportResult(ctx, result); ok {
				return transportResult
			}
			// A short job can be assigned and finish between two lifecycle
			// samples. Re-query GitHub after process exit before classifying the
			// zero-exit container as unassigned.
			if !assigned && !busyObserved {
				if failure := observeBeforeDeadline(); failure.err != nil {
					return failure
				}
			}
			if !online && !time.Now().Before(onlineDeadlineAt) {
				return runnerDeadlineFailure(runnerID, "online", timing.OnlineTimeout, lastObservationErr)
			}
			if !assigned {
				correlationDeadline := assignmentDeadlineAt
				if !online {
					correlationDeadline = onlineDeadlineAt
				}
				if busyObserved {
					// The runner can exit before the next live poll while Actions job
					// metadata is still converging. Preserve enough fresh, bounded
					// grace for at least two post-exit correlation attempts even when
					// PollInterval exceeds the original assignment timeout.
					correlationDeadline = time.Now().Add(postBusyCorrelationGrace(timing))
				}
				job, correlated, err := w.waitForAssignedJobEvidence(
					ctx, intent, containerName, runnerID, correlationSince,
					correlationDeadline, timing.PollInterval,
				)
				if err != nil {
					lastObservationErr = err
				}
				if correlated {
					if markErr := w.markCorrelatedAssignment(intent, containerName, runnerID, job.ID); markErr != nil {
						return lifecycleFailure("github_job_correlation_failed", markErr)
					}
					assigned = true
				}
			}
			if !online && !time.Now().Before(onlineDeadlineAt) {
				return runnerDeadlineFailure(runnerID, "online", timing.OnlineTimeout, lastObservationErr)
			}
			if !assigned {
				if busyObserved {
					failure := fmt.Errorf("runner %d received a job but its exact GitHub job id could not be correlated", runnerID)
					if lastObservationErr != nil {
						failure = fmt.Errorf("%v: last correlation error: %w", failure, lastObservationErr)
					}
					out := lifecycleFailure("github_job_correlation_failed", failure)
					out.exitCode = result.exitCode
					out.timedOut = result.timedOut
					out.delivered = true
					return out
				}
				failure := fmt.Errorf("runner %d exited with code %d before GitHub reported a job assignment", runnerID, result.exitCode)
				_ = w.deps.Emit().EmitRunnerExitedUnassigned(cornerstone.RunnerExitedUnassignedFields{
					Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
					ContainerName: containerName, GitHubRunnerID: runnerID,
					ExitCode: result.exitCode,
				})
				out := lifecycleFailure("runner_exited_unassigned", failure)
				out.exitCode = result.exitCode
				out.timedOut = result.timedOut
				out.unassigned = true
				return out
			}
			return lifecycleResult{exitCode: result.exitCode, timedOut: result.timedOut}
		case <-pollC:
			if failure := observeBeforeDeadline(); failure.err != nil {
				return failure
			}
		case <-onlineFinalC:
			onlineFinalC = nil
			if !online {
				if failure := observeBeforeDeadline(); failure.err != nil {
					return failure
				}
			}
		case <-assignmentFinalC:
			assignmentFinalC = nil
			if !assigned {
				if failure := observeBeforeDeadline(); failure.err != nil {
					return failure
				}
			}
		case <-onlineTimer.C:
			if !online {
				return runnerDeadlineFailure(runnerID, "online", timing.OnlineTimeout, lastObservationErr)
			}
		case <-assignmentTimer.C:
			if !assigned && !busyObserved {
				return runnerDeadlineFailure(runnerID, "assignment", timing.AssignmentTimeout, lastObservationErr)
			}
		}

		// A timer may race with the observation that satisfies its condition.
		// Disable elapsed deadlines once the corresponding state is observed.
		if online {
			stopTimer(onlineTimer)
			stopTimer(onlineFinalTimer)
			onlineFinalC = nil
		}
		if busyObserved {
			stopTimer(assignmentTimer)
			stopTimer(assignmentFinalTimer)
			assignmentFinalC = nil
		}
		if assigned {
			if pollC != nil {
				poll.Stop()
				pollC = nil
			}
		}
	}
}

func (w *SpawnWorker) waitForAssignedJobEvidence(
	ctx context.Context,
	intent SpawnIntent,
	containerName string,
	runnerID int64,
	since time.Time,
	deadline time.Time,
	retryInterval time.Duration,
) (github.WorkflowJob, bool, error) {
	var lastErr error
	attempted := false
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return github.WorkflowJob{}, false, lastErr
		}
		minimumAttemptWindow := min(retryInterval, 50*time.Millisecond)
		if attempted && remaining <= minimumAttemptWindow {
			return github.WorkflowJob{}, false, lastErr
		}
		attemptCtx, cancelAttempt := context.WithDeadline(ctx, deadline)
		job, found, err := w.findAssignedJob(
			attemptCtx, intent, containerName, runnerID, since,
		)
		attempted = true
		cancelAttempt()
		if found {
			return job, true, nil
		}
		if err != nil && !(errors.Is(err, context.DeadlineExceeded) && lastErr != nil) {
			lastErr = err
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return github.WorkflowJob{}, false, lastErr
		}
		delay := min(retryInterval, remaining)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return github.WorkflowJob{}, false, ctx.Err()
		case <-timer.C:
		}
	}
}

func finalObservationLead(timeout time.Duration) time.Duration {
	lead := timeout / 2
	if lead > time.Second {
		return time.Second
	}
	return lead
}

func postBusyCorrelationGrace(timing LifecycleTiming) time.Duration {
	return max(timing.AssignmentTimeout, 3*timing.PollInterval)
}

func runnerDeadlineFailure(
	runnerID int64,
	phase string,
	timeout time.Duration,
	lastObservationErr error,
) lifecycleResult {
	detail := fmt.Sprintf("runner %d did not become online within %s", runnerID, timeout)
	reason := "runner_online_timeout"
	if phase == "assignment" {
		detail = fmt.Sprintf("runner %d did not receive a job within %s", runnerID, timeout)
		reason = "runner_assignment_timeout"
	}
	if lastObservationErr != nil {
		return lifecycleFailure(
			reason,
			fmt.Errorf("%s: last observation: %w", detail, lastObservationErr),
		)
	}
	return lifecycleFailure(reason, errors.New(detail))
}

func (w *SpawnWorker) findAssignedJob(
	ctx context.Context,
	intent SpawnIntent,
	containerName string,
	runnerID int64,
	since time.Time,
) (github.WorkflowJob, bool, error) {
	candidateAPICalls := 0
	for _, candidate := range intent.CandidateJobs[:min(len(intent.CandidateJobs), defaultExactCandidateProbes)] {
		candidateAPICalls++
		job, lim, err := w.deps.GitHub().GetWorkflowJob(ctx, intent.Repo, candidate.ID)
		w.deps.RecordRateLimit(intent.Scope, lim)
		w.recordRunnerOperation(intent.Repo, runnerOperationGetJob, err)
		if err != nil {
			if github.ErrorStatus(err) == http.StatusNotFound {
				continue
			}
			return github.WorkflowJob{}, false, err
		}
		if !jobMatchesRunner(job, runnerID, containerName) {
			continue
		}
		if job.ID <= 0 {
			return github.WorkflowJob{}, false, errors.New("github job correlation returned an invalid job id")
		}
		return job, true, nil
	}
	priorityRunIDs := make([]int64, 0, len(intent.CandidateJobs))
	seenRunIDs := make(map[int64]bool, len(intent.CandidateJobs))
	for _, candidate := range intent.CandidateJobs {
		if candidate.RunID > 0 && !seenRunIDs[candidate.RunID] {
			seenRunIDs[candidate.RunID] = true
			priorityRunIDs = append(priorityRunIDs, candidate.RunID)
		}
	}
	remainingAPICalls := defaultJobCorrelationMaxCalls - candidateAPICalls
	result, err := w.deps.GitHub().FindRecentWorkflowJobByRunner(
		ctx, intent.Repo, runnerID, containerName,
		github.RecentJobSearchBounds{
			Since: since, PriorityRunIDs: priorityRunIDs,
			MaxRuns:     max(defaultJobCorrelationMaxRuns, len(priorityRunIDs)),
			MaxAPICalls: remainingAPICalls,
		},
	)
	w.deps.RecordRateLimit(intent.Scope, result.RateLimit)
	w.recordRunnerOperation(intent.Repo, runnerOperationFindRecentJob, err)
	if err != nil {
		return github.WorkflowJob{}, false, err
	}
	if !result.Found {
		return github.WorkflowJob{}, false, nil
	}
	if result.Job.ID <= 0 {
		return github.WorkflowJob{}, false, errors.New("github recent job correlation returned an invalid job id")
	}
	return result.Job, true, nil
}

func (w *SpawnWorker) markCorrelatedAssignment(
	intent SpawnIntent,
	containerName string,
	runnerID int64,
	jobID int64,
) error {
	if jobID <= 0 {
		return errors.New("cannot mark assignment without a positive GitHub job id")
	}
	now := w.deps.Clock().Now()
	if w.deps.State().MarkOnline(intent.SpawnID, now) {
		_ = w.deps.Emit().EmitRunnerOnline(cornerstone.RunnerOnlineFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerName: containerName, GitHubRunnerID: runnerID,
		})
	}
	if w.deps.State().MarkAssigned(intent.SpawnID, jobID, now) {
		_ = w.deps.Emit().EmitJobAssigned(cornerstone.JobAssignedFields{
			Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
			ContainerName: containerName, GitHubRunnerID: runnerID, GitHubJobID: jobID,
		})
		return nil
	}
	return fmt.Errorf("state rejected correlated job %d for spawn %s", jobID, intent.SpawnID)
}

func jobMatchesRunner(job github.WorkflowJob, runnerID int64, runnerName string) bool {
	if job.Status != "in_progress" && job.Status != "completed" {
		return false
	}
	if job.RunnerID > 0 && runnerID > 0 {
		return job.RunnerID == runnerID
	}
	return runnerName != "" && job.RunnerName == runnerName
}

func normalizedLifecycleTiming(timing LifecycleTiming) LifecycleTiming {
	defaults := DefaultLifecycleTiming()
	if timing.OnlineTimeout <= 0 {
		timing.OnlineTimeout = defaults.OnlineTimeout
	}
	if timing.AssignmentTimeout <= 0 {
		timing.AssignmentTimeout = defaults.AssignmentTimeout
	}
	if timing.PollInterval <= 0 {
		timing.PollInterval = defaults.PollInterval
	}
	if timing.CleanupRetryInterval <= 0 {
		timing.CleanupRetryInterval = defaults.CleanupRetryInterval
	}
	return timing
}

func lifecycleFailure(reason string, err error) lifecycleResult {
	return lifecycleResult{exitCode: -1, err: err, failureReason: reason}
}

func lifecycleTransportResult(ctx context.Context, result backendExit) (lifecycleResult, bool) {
	if result.timedOut {
		return lifecycleResult{exitCode: result.exitCode, timedOut: true}, true
	}
	if err := ctx.Err(); err != nil {
		return lifecycleFailure("runner_observation_cancelled", err), true
	}
	return lifecycleResult{}, false
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
