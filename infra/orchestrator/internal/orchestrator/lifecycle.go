package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
)

const (
	defaultRunnerOnlineTimeout     = 60 * time.Second
	defaultRunnerAssignmentTimeout = 120 * time.Second
	defaultRunnerPollInterval      = 2 * time.Second
)

// DefaultLifecycleTiming is the production registration and assignment
// observation policy. Tests inject shorter values through SpawnDeps.
func DefaultLifecycleTiming() LifecycleTiming {
	return LifecycleTiming{
		OnlineTimeout:     defaultRunnerOnlineTimeout,
		AssignmentTimeout: defaultRunnerAssignmentTimeout,
		PollInterval:      defaultRunnerPollInterval,
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
	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()

	exitCh := make(chan backendExit, 1)
	go func() {
		exitCode, timedOut := w.deps.Backend().WaitForExit(waitCtx, h, wallTimeout)
		exitCh <- backendExit{exitCode: exitCode, timedOut: timedOut}
	}()

	online := false
	assigned := false
	lastObservationErr := error(nil)

	observe := func() lifecycleResult {
		runner, _, err := w.deps.GitHub().GetRunner(ctx, intent.Repo, runnerID)
		if err != nil {
			lastObservationErr = err
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
			assigned = true
			if w.deps.State().MarkAssigned(intent.SpawnID, w.deps.Clock().Now()) {
				_ = w.deps.Emit().EmitJobAssigned(cornerstone.JobAssignedFields{
					Scope: intent.Scope, Repo: intent.Repo, SpawnID: intent.SpawnID,
					ContainerName: containerName, GitHubRunnerID: runnerID,
				})
			}
		}
		return lifecycleResult{}
	}

	if failure := observe(); failure.err != nil {
		return failure
	}

	poll := time.NewTicker(timing.PollInterval)
	defer poll.Stop()
	onlineTimer := time.NewTimer(timing.OnlineTimeout)
	defer stopTimer(onlineTimer)
	assignmentTimer := time.NewTimer(timing.AssignmentTimeout)
	defer stopTimer(assignmentTimer)
	if online {
		stopTimer(onlineTimer)
	}
	if assigned {
		stopTimer(assignmentTimer)
	}

	for {
		select {
		case <-ctx.Done():
			return lifecycleFailure("runner_observation_cancelled", ctx.Err())
		case result := <-exitCh:
			if !assigned {
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
		case <-poll.C:
			if failure := observe(); failure.err != nil {
				return failure
			}
		case <-onlineTimer.C:
			if !online {
				detail := fmt.Sprintf("runner %d did not become online within %s", runnerID, timing.OnlineTimeout)
				if lastObservationErr != nil {
					detail = fmt.Sprintf("%s: last observation: %v", detail, lastObservationErr)
				}
				return lifecycleFailure("runner_online_timeout", errors.New(detail))
			}
		case <-assignmentTimer.C:
			if !assigned {
				detail := fmt.Sprintf("runner %d did not receive a job within %s", runnerID, timing.AssignmentTimeout)
				if lastObservationErr != nil {
					detail = fmt.Sprintf("%s: last observation: %v", detail, lastObservationErr)
				}
				return lifecycleFailure("runner_assignment_timeout", errors.New(detail))
			}
		}

		// A timer may race with the observation that satisfies its condition.
		// Disable elapsed deadlines once the corresponding state is observed.
		if online {
			stopTimer(onlineTimer)
		}
		if assigned {
			stopTimer(assignmentTimer)
		}
	}
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
	return timing
}

func lifecycleFailure(reason string, err error) lifecycleResult {
	return lifecycleResult{exitCode: -1, err: err, failureReason: reason}
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
