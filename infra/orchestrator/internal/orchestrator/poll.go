package orchestrator

import (
	"context"
	"errors"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
)

// ScopeRef is what the poll loop needs to know about its scope.
type ScopeRef struct {
	Name             string
	GlobalMaxRunners int
	PollIntervalSec  int
	Repos            []RepoRef
}

// RepoRef is a single repo within a scope.
type RepoRef struct {
	Repo          string
	MaxConcurrent int
}

// Poll is one per-scope poll loop.
type Poll struct {
	scope ScopeRef
	deps  PollDeps
}

// NewPoll constructs a per-scope poll loop.
func NewPoll(scope ScopeRef, deps PollDeps) *Poll {
	return &Poll{scope: scope, deps: deps}
}

// pollIntervalDuration converts the scope's poll-interval seconds into
// a Duration. Extracted so mutation testing can directly assert the
// multiplication operator with an exact-value test.
func pollIntervalDuration(intervalSec int) time.Duration {
	return time.Duration(intervalSec) * time.Second
}

// Run blocks the goroutine until ctx is cancelled; ticks on the scope's
// poll interval and enqueues spawn intents.
func (p *Poll) Run(ctx context.Context) {
	interval := pollIntervalDuration(p.scope.PollIntervalSec)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		p.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-p.deps.Clock().After(interval):
		}
	}
}

// tick runs one poll cycle.
func (p *Poll) tick(ctx context.Context) {
	// Bug #2 fix: record this tick to update the /healthz freshness signal.
	p.deps.RecordPollTick()
	// Shutdown drain and unresolved teardown debt are scope-wide admission
	// barriers. TryReserve repeats this check atomically with capacity changes,
	// closing the race with a teardown failure that lands during this tick.
	if p.deps.SchedulingBlocked() {
		return
	}

	// If we're in a rate-limit pause for this scope, check if it's cleared.
	if p.deps.IsRateLimited(p.scope.Name) {
		if p.deps.MaybeClearRateLimit(p.scope.Name) {
			rem, lim, reset := p.deps.RateLimitContextFor(p.scope.Name)
			_ = p.deps.Emit().EmitRatelimitResumed(cornerstone.RateLimitFields{
				Scope: p.scope.Name, Remaining: rem, Limit: lim, ResetISO: reset,
			})
		} else {
			return // still paused; skip this tick
		}
	}

	rem, lim, reset := p.deps.RateLimitContextFor(p.scope.Name)
	_ = p.deps.Emit().EmitPollTick(cornerstone.PollTickFields{
		Scope:              p.scope.Name,
		RateLimitRemaining: rem,
		RateLimitLimit:     lim,
		RateLimitResetISO:  reset,
	})

	for _, repo := range p.scope.Repos {
		// Half-open transition? (B4)
		p.deps.BreakerMaybeHalfOpen(repo.Repo)
		if p.deps.BreakerIsOpen(repo.Repo) {
			continue
		}

		p.deps.RecordPollAttempt(repo.Repo)
		labels, err := p.deps.LabelsForRepo(repo.Repo)
		if err != nil {
			p.recordPollFailure(repo.Repo, "runner_config", err.Error())
			continue
		}
		demand, err := p.deps.GitHub().EligibleQueuedJobs(ctx, repo.Repo, labels)
		if err != nil {
			lim := github.ErrorRateLimit(err)
			p.deps.RecordRateLimit(p.scope.Name, lim)
			p.recordPollFailure(repo.Repo, classifyPollError(err), err.Error())
			p.handlePollError(repo.Repo, err)
			continue
		}
		p.deps.RecordRateLimit(p.scope.Name, demand.RateLimit)
		queued := demand.Count()
		p.recordPollSuccess(repo.Repo, queued)
		if queued > 0 {
			_ = p.deps.Emit().EmitPollQueuedJobsObserved(cornerstone.PollQueuedJobsObservedFields{
				Scope: p.scope.Name, Repo: repo.Repo, Count: queued,
			})
		}

		// Clamp via min/max (Go 1.21+ builtins) — eliminates the boundary
		// operators that confound mutation testing.
		repoAvail := repo.MaxConcurrent - p.deps.InFlight(repo.Repo)
		globalAvail := p.scope.GlobalMaxRunners - p.deps.GlobalInFlight()
		avail := max(min(repoAvail, globalAvail), 0)
		// GitHub continues to report a job as queued while a reserved JIT
		// runner is registering or online but not yet assigned. Subtract that
		// repo-specific delivered capacity before reserving again; otherwise a
		// slow registration can create one runner per poll for one job.
		uncoveredDemand := max(queued-p.deps.DemandCoverage(repo.Repo), 0)
		toSpawn := min(uncoveredDemand, avail)

		for i := 0; i < toSpawn; i++ {
			intent := SpawnIntent{
				Scope:         p.scope.Name,
				Repo:          repo.Repo,
				SpawnID:       p.deps.NewSpawnID(),
				CandidateJobs: append([]github.WorkflowJob(nil), demand.Jobs...),
			}
			if !p.deps.TryReserve(intent.SpawnID, intent.Repo, repo.MaxConcurrent, p.scope.GlobalMaxRunners) {
				break
			}
			select {
			case p.deps.IntentChannel() <- intent:
			case <-ctx.Done():
				p.deps.ReleaseReservation(intent.SpawnID)
				return
			}
		}
	}
}

func (p *Poll) recordPollFailure(repo, class, detail string) {
	opened, consecutive := p.deps.RecordPollFailure(repo, class, detail)
	if opened {
		_ = p.deps.Emit().EmitBreakerOpened(cornerstone.BreakerFields{
			Scope: p.scope.Name, Repo: repo, ConsecutiveFailures: consecutive,
		})
	}
}

func (p *Poll) recordPollSuccess(repo string, queued int) {
	if p.deps.RecordPollSuccess(repo, queued) {
		_ = p.deps.Emit().EmitBreakerClosed(cornerstone.BreakerFields{
			Scope: p.scope.Name, Repo: repo,
		})
	}
}

func classifyPollError(err error) string {
	switch {
	case errors.Is(err, github.ErrRateLimited):
		return "github_rate_limited"
	case errors.Is(err, github.ErrAuthFailed):
		return "github_auth_failed"
	default:
		return "github_demand_failed"
	}
}

func (p *Poll) handlePollError(repo string, err error) {
	switch {
	case errors.Is(err, github.ErrRateLimited):
		if p.deps.MarkRateLimited(p.scope.Name) {
			rem, lim, reset := p.deps.RateLimitContextFor(p.scope.Name)
			_ = p.deps.Emit().EmitRatelimitPaused(cornerstone.RateLimitFields{
				Scope: p.scope.Name, Remaining: rem, Limit: lim, ResetISO: reset,
			})
		}
	case errors.Is(err, github.ErrAuthFailed):
		_ = p.deps.Emit().EmitAuthDegraded(cornerstone.AuthDegradedFields{
			Scope: p.scope.Name, Repo: repo, Status: github.ErrorStatus(err),
		})
	default:
		// Other errors: do not retry-storm or crash; next poll tries again.
		// Caller's logger (set on the emitter's writer) carries the detail.
	}
}
