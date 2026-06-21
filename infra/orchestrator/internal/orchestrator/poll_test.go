package orchestrator

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/stretchr/testify/require"
)

// pollDeps wraps spawnDeps + an intent channel and rate-limit state.
type pollDeps struct {
	*spawnDeps
	intents       chan SpawnIntent
	pollTickCount atomic.Int64
	rl            struct {
		paused      atomic.Bool
		stickPaused atomic.Bool // when set, MaybeClearRateLimit never clears
		remaining   int
		limit       int
		reset       string
	}
}

func newPollDeps(t *testing.T) *pollDeps {
	return &pollDeps{
		spawnDeps: newSpawnDeps(t),
		intents:   make(chan SpawnIntent, 32),
	}
}

func (d *pollDeps) IntentChannel() chan<- SpawnIntent { return d.intents }
func (d *pollDeps) InFlight(repo string) int          { return d.st.InFlight(repo) }
func (d *pollDeps) GlobalInFlight() int               { return d.st.GlobalInFlight() }
func (d *pollDeps) BreakerIsOpen(repo string) bool    { return d.breakers.IsOpen(repo) }
func (d *pollDeps) BreakerMaybeHalfOpen(repo string) bool {
	return d.breakers.MaybeHalfOpen(repo)
}
func (d *pollDeps) RateLimitContextFor(_ string) (int, int, string) {
	return d.rl.remaining, d.rl.limit, d.rl.reset
}
func (d *pollDeps) RecordRateLimit(_ string, _ github.RateLimit) {}
func (d *pollDeps) MarkRateLimited(_ string)                     { d.rl.paused.Store(true) }
func (d *pollDeps) IsRateLimited(_ string) bool                  { return d.rl.paused.Load() }
func (d *pollDeps) MaybeClearRateLimit(_ string) bool {
	// Honour rl.stickPaused: when set, never clear (so the "still paused;
	// skip this tick" return in tick() is exercised).
	if d.rl.stickPaused.Load() {
		return false
	}
	if d.rl.paused.Load() {
		d.rl.paused.Store(false)
		return true
	}
	return false
}

var spawnIDCounter atomic.Int64

func (d *pollDeps) NewSpawnID() string {
	n := spawnIDCounter.Add(1)
	return time.Now().Format("20060102T150405") + "-" + itoa(n)
}

func (d *pollDeps) RecordPollTick() { d.pollTickCount.Add(1) }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 8)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// --- tests ---

// TestPoll_EnqueuesSpawnsUpToCaps verifies the poll loop respects caps.
//
// Instead of mutating the live httptest server, we use a fakeGitHubBackend
// instance the test controls directly.
func TestPoll_EnqueuesSpawnsUpToCaps(t *testing.T) {
	d := newPollDeps(t)

	// Replace the github client with one bound to our fakeGitHubBackend.
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set queued=5, cap=3 → should enqueue 3 intents in one tick.
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 5
	srv.mu.Unlock()

	p.tick(ctx)

	require.Len(t, d.intents, 3)
}

func TestPoll_SkipsBreakerOpen(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 5
	srv.mu.Unlock()
	d.breakers.open["o/r"] = true

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	NewPoll(scope, d).tick(context.Background())

	require.Empty(t, d.intents)
}

func TestPoll_RateLimitPauseAndResume(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queueErrCode["o/r"] = 429
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)
	p.tick(context.Background())

	require.True(t, d.IsRateLimited("s"))
	d.requireEmitted(t, cornerstone.EventRatelimitPaused)
	require.Empty(t, d.intents)

	// Clear the 429 — on next tick, MaybeClearRateLimit returns true, ratelimit.resumed fires.
	srv.mu.Lock()
	delete(srv.queueErrCode, "o/r")
	srv.queuedFor["o/r"] = 1
	srv.mu.Unlock()
	p.tick(context.Background())
	d.requireEmitted(t, cornerstone.EventRatelimitResumed)
}

func TestPoll_AuthFailureEmitsAuthDegraded(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queueErrCode["o/r"] = 401
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	NewPoll(scope, d).tick(context.Background())

	d.requireEmitted(t, cornerstone.EventAuthDegraded)
}

func TestPoll_Run_ExitsOnContextCancel(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 0
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	// Let one tick happen on the real clock; then cancel.
	time.Sleep(50 * time.Millisecond)
	d.clk.Advance(6 * time.Second) // unblock the After(interval) wait
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit on cancel")
	}
}

func TestPoll_RecordsTickEveryCycle(t *testing.T) {
	// Bug #2 regression: poll.tick must call RecordPollTick so /healthz
	// stays fresh.
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 0
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)
	p.tick(context.Background())
	p.tick(context.Background())
	require.Equal(t, int64(2), d.pollTickCount.Load(),
		"RecordPollTick must fire on every tick (bug #2 regression)")
}

// --- Mutation-kill regression tests ---

// Mutation kill: poll.go:93 — `if queued > 0`. Mutation to `>= 0` would
// emit poll.queued_jobs_observed even when there are zero queued jobs.
func TestPoll_DoesNotEmitQueuedJobsObserved_WhenZero(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 0
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	NewPoll(scope, d).tick(context.Background())
	require.NotContains(t, d.emBuf.String(), cornerstone.EventPollQueuedJobsObserved,
		"queued=0 must NOT emit poll.queued_jobs_observed")
}

// Mutation kill: poll.go:99 — `avail := repo.MaxConcurrent - in_flight`.
// Asserts exact spawn count obeys the per-repo cap minus existing in-flight.
func TestPoll_RespectsRepoCapMinusInFlight(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 10
	srv.mu.Unlock()

	d.st.IncrementInFlight("o/r")
	d.st.IncrementInFlight("o/r")
	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 100, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 5}},
	}
	NewPoll(scope, d).tick(context.Background())
	require.Len(t, d.intents, 3, "must spawn exactly repo_cap - in_flight = 3")
}

// Mutation kill: poll.go global-cap subtraction (`GlobalMaxRunners -
// GlobalInFlight`). GlobalInFlight must be NON-ZERO for the subtraction
// to be observable — otherwise `+` and `-` are indistinguishable.
func TestPoll_GlobalCapBindsBeforeRepoCap(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 10
	srv.mu.Unlock()

	// Another repo already has 2 in-flight, so GlobalInFlight()=2.
	d.st.IncrementInFlight("other/repo")
	d.st.IncrementInFlight("other/repo")

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 4, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 10}},
	}
	NewPoll(scope, d).tick(context.Background())
	require.Len(t, d.intents, 2,
		"global cap minus in-flight (4-2=2) must bind below repo cap (10); "+
			"mutating `-` → `+` yields 6 spawns")
}

// Mutation kill: poll.go:103 — `if avail < 0 { avail = 0 }`.
// Without the clamp, an over-committed repo could produce negative spawn count.
func TestPoll_AvailNegativeClampedToZero(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 5
	srv.mu.Unlock()
	for i := 0; i < 5; i++ {
		d.st.IncrementInFlight("o/r")
	}
	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 2}},
	}
	NewPoll(scope, d).tick(context.Background())
	require.Empty(t, d.intents, "negative avail must clamp to 0 spawns")
}

// Mutation kill: poll.go:107 — `if toSpawn > avail`. Asserts toSpawn is
// clamped to avail when queued exceeds available capacity.
// Run() returns immediately if context is already cancelled before the
// loop runs (covers poll.go:43-44).
func TestPoll_Run_ReturnsImmediatelyOnCancelledCtx(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 0
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on cancelled context")
	}
}

// Rate-limit pause persists across multiple ticks (covers the "still
// paused; skip this tick" return at poll.go:68-70).
func TestPoll_RateLimitedTickReturnsEarly(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queueErrCode["o/r"] = 429
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	p := NewPoll(scope, d)
	// First tick: rate-limited, marks scope paused.
	p.tick(context.Background())
	require.True(t, d.IsRateLimited("s"))

	// Lock the pause so MaybeClearRateLimit returns false on the next tick.
	d.rl.stickPaused.Store(true)
	initialEvents := strings.Count(d.emBuf.String(), `"event.sub.type"`)
	p.tick(context.Background())
	// Tick should have returned early after RecordPollTick — no additional
	// Cornerstone events should fire (no poll.tick emission, no queue calls).
	require.Equal(t, initialEvents, strings.Count(d.emBuf.String(), `"event.sub.type"`))
}

func TestPoll_ToSpawnClampedToAvail(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 100 // way more than capacity
	srv.mu.Unlock()
	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 4, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	NewPoll(scope, d).tick(context.Background())
	require.Len(t, d.intents, 3, "toSpawn must clamp to min(queued, avail)=3")
}

// Mutation kill: poll.go pollIntervalDuration — `intervalSec * time.Second`.
// Exact-value assert kills arithmetic mutations on the multiplication.
func TestPollIntervalDuration(t *testing.T) {
	require.Equal(t, 15*time.Second, pollIntervalDuration(15))
	require.Equal(t, 0*time.Second, pollIntervalDuration(0))
	require.Equal(t, 60*time.Second, pollIntervalDuration(60))
}

func TestPoll_PollTickEventFiresEveryCycle(t *testing.T) {
	d := newPollDeps(t)
	gh, srv := newFakeGitHubClient(t)
	d.gh = gh
	srv.mu.Lock()
	srv.queuedFor["o/r"] = 0
	srv.mu.Unlock()

	scope := ScopeRef{
		Name: "s", GlobalMaxRunners: 10, PollIntervalSec: 5,
		Repos: []RepoRef{{Repo: "o/r", MaxConcurrent: 3}},
	}
	NewPoll(scope, d).tick(context.Background())
	d.requireEmitted(t, cornerstone.EventPollTick)
}
