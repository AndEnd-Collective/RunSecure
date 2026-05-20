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

// Run blocks the goroutine until ctx is cancelled; ticks on the scope's
// poll interval and enqueues spawn intents.
func (p *Poll) Run(ctx context.Context) {
	interval := time.Duration(p.scope.PollIntervalSec) * time.Second
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

		queued, err := p.deps.GitHub().QueuedJobs(ctx, repo.Repo)
		if err != nil {
			p.handlePollError(repo.Repo, err)
			continue
		}
		if queued > 0 {
			_ = p.deps.Emit().EmitPollQueuedJobsObserved(cornerstone.PollQueuedJobsObservedFields{
				Scope: p.scope.Name, Repo: repo.Repo, Count: queued,
			})
		}

		avail := repo.MaxConcurrent - p.deps.InFlight(repo.Repo)
		if g := p.scope.GlobalMaxRunners - p.deps.GlobalInFlight(); g < avail {
			avail = g
		}
		if avail < 0 {
			avail = 0
		}
		toSpawn := queued
		if toSpawn > avail {
			toSpawn = avail
		}

		for i := 0; i < toSpawn; i++ {
			intent := SpawnIntent{
				Scope:   p.scope.Name,
				Repo:    repo.Repo,
				SpawnID: p.deps.NewSpawnID(),
			}
			select {
			case p.deps.IntentChannel() <- intent:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (p *Poll) handlePollError(repo string, err error) {
	switch {
	case errors.Is(err, github.ErrRateLimited):
		p.deps.MarkRateLimited(p.scope.Name)
		rem, lim, reset := p.deps.RateLimitContextFor(p.scope.Name)
		_ = p.deps.Emit().EmitRatelimitPaused(cornerstone.RateLimitFields{
			Scope: p.scope.Name, Remaining: rem, Limit: lim, ResetISO: reset,
		})
	case errors.Is(err, github.ErrAuthFailed):
		_ = p.deps.Emit().EmitAuthDegraded(cornerstone.AuthDegradedFields{
			Scope: p.scope.Name, Repo: repo, Status: 401,
		})
	default:
		// Other errors: do not retry-storm or crash; next poll tries again.
		// Caller's logger (set on the emitter's writer) carries the detail.
	}
}
