// Package orchestrator wires GitHub polling + docker spawning + state.
//
// Two goroutines per scope:
//   - Poll loop (poll.go): owns timing, enqueues spawn intents.
//   - Spawn workers (spawn.go): drain the intent channel, execute steps 0-7.
//
// Decoupling poll from execution keeps the poll loop non-blocking; a slow
// docker create cannot delay the next poll tick.
package orchestrator

import (
	"context"
	"errors"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
)

// SpawnIntent is what the poll loop enqueues; spawn workers consume.
type SpawnIntent struct {
	Scope, Repo, SpawnID string
}

// ClockLike is the minimal time abstraction the orchestrator uses; the
// concrete impl is in internal/clock.
type ClockLike interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// StateLike is the surface the orchestrator uses from internal/state,
// abstracted for testability.
type StateLike interface {
	InFlight(repo string) int
	GlobalInFlight() int
	IncrementInFlight(repo string)
	DecrementInFlight(repo string)
	AcquireSemaphores(repo string, repoCap, globalCap int) bool
	ReleaseSemaphores(repo string)
}

// BreakerMap is per-repo breaker storage. Implementations are concrete in
// production; tests inject a map.
type BreakerMap interface {
	IsOpen(repo string) bool
	MaybeHalfOpen(repo string) bool
	RecordSuccess(repo string)
	RecordFailure(repo string) (opened bool, consecutiveFailures int)
}

// TokenBucket is the B1 rate limiter.
type TokenBucket interface {
	TryTake() bool
}

// EgressGenerator renders per-spawn squid/haproxy/dnsmasq configs.
type EgressGenerator interface {
	Render(spawnID string, r *runneryml.Runner) (configDir string, err error)
}

// RunnerYMLSnapshot is a parsed runner.yml + the resolved image digest for
// its runtime. Spawn workers consume this; production caches it per repo
// keyed on file mtime.
type RunnerYMLSnapshot struct {
	YML         *runneryml.Runner
	ImageDigest string // resolved digest for the runner image
}

// PollDeps is the dependency surface the poll loop needs.
type PollDeps interface {
	GitHub() *github.Client
	Emit() *cornerstone.Emitter
	Clock() ClockLike

	InFlight(repo string) int
	GlobalInFlight() int
	BreakerIsOpen(repo string) bool
	BreakerMaybeHalfOpen(repo string) bool

	IntentChannel() chan<- SpawnIntent

	RateLimitContextFor(scope string) (remaining int, limit int, reset string)
	RecordRateLimit(scope string, lim github.RateLimit)
	MarkRateLimited(scope string)
	IsRateLimited(scope string) bool
	MaybeClearRateLimit(scope string) bool

	NewSpawnID() string
}

// SpawnDeps is the dependency surface a SpawnWorker needs.
type SpawnDeps interface {
	GitHub() *github.Client
	Docker() docker.Client
	Emit() *cornerstone.Emitter
	Clock() ClockLike
	Egress() EgressGenerator
	RunnerYML(repo string) (*RunnerYMLSnapshot, error)
	State() StateLike

	GlobalMaxRunners() int
	RepoMaxConcurrent(repo string) int
	ScopeName() string
	ProxyImageDigest() string
	RunnerImageDigestFor(runtime string) string
	SeccompProfileHostPath(name string) string

	RateLimiter() TokenBucket
	Breakers() BreakerMap
}

// Errors surfaced through SpawnWorker.Execute for callers that want to
// log/route differently.
var (
	ErrSemaphoreUnavailable = errors.New("orchestrator: failed to acquire semaphore (concurrency)")
	ErrRateLimitBackoff     = errors.New("orchestrator: spawn rate-limit hit (B1)")
)

// shutdown sentinel; callers use ctx cancellation rather than this.
var _ = context.Canceled
