package orchestrator

import (
	"context"
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
	intents chan SpawnIntent
	rl      struct {
		paused   atomic.Bool
		remaining int
		limit     int
		reset     string
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
func (d *pollDeps) MarkRateLimited(_ string)                { d.rl.paused.Store(true) }
func (d *pollDeps) IsRateLimited(_ string) bool             { return d.rl.paused.Load() }
func (d *pollDeps) MaybeClearRateLimit(_ string) bool {
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
