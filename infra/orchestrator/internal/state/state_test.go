package state

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireReleaseSemaphores_HappyPath(t *testing.T) {
	s := New()
	require.True(t, s.AcquireSemaphores("o/r", 5, 10))
	require.Equal(t, 1, s.InFlight("o/r"))
	require.Equal(t, 1, s.GlobalInFlight())
	s.ReleaseSemaphores("o/r")
	require.Equal(t, 0, s.InFlight("o/r"))
}

func TestAcquireSemaphores_RepoCap(t *testing.T) {
	s := New()
	require.True(t, s.AcquireSemaphores("o/r", 1, 10))
	require.False(t, s.AcquireSemaphores("o/r", 1, 10), "second acquire must fail")
}

func TestAcquireSemaphores_GlobalCap(t *testing.T) {
	s := New()
	require.True(t, s.AcquireSemaphores("o/a", 5, 1))
	require.False(t, s.AcquireSemaphores("o/b", 5, 1), "global cap reached")
}

func TestReleaseSemaphores_Floor(t *testing.T) {
	s := New()
	s.ReleaseSemaphores("o/r") // ok even if never acquired
	require.Equal(t, 0, s.InFlight("o/r"))
}

// Mutation kill: state.go:105 — `if r.InFlight > 0` clamp on Decrement.
// Mutation `>=` would let InFlight go negative. The Floor check above passes
// for ReleaseSemaphores but doesn't directly test DecrementInFlight.
func TestDecrementInFlight_FloorAtZero(t *testing.T) {
	s := New()
	s.DecrementInFlight("o/r") // never incremented; mutated >= would let it go negative
	require.Equal(t, 0, s.InFlight("o/r"))
	s.DecrementInFlight("o/r")
	require.Equal(t, 0, s.InFlight("o/r"))
}

func TestIncrementDecrement(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/r")
	s.IncrementInFlight("o/r")
	require.Equal(t, 2, s.InFlight("o/r"))
	s.DecrementInFlight("o/r")
	require.Equal(t, 1, s.InFlight("o/r"))
}

func TestRateLimit(t *testing.T) {
	s := New()
	reset := time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC)
	s.SetRateLimit(4321, 5000, reset)
	rem, lim, r := s.RateLimit()
	require.Equal(t, 4321, rem)
	require.Equal(t, 5000, lim)
	require.True(t, reset.Equal(r))
}

func TestSnapshot(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/a")
	s.IncrementInFlight("o/b")
	s.IncrementInFlight("o/b")
	s.SetRateLimit(10, 100, time.Now())
	snap := s.Snapshot()
	require.Equal(t, 3, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["o/a"].InFlight)
	require.Equal(t, 2, snap.PerRepo["o/b"].InFlight)
	require.Equal(t, 10, snap.RateLimitRemaining)
}

func TestAllRepos(t *testing.T) {
	s := New()
	s.IncrementInFlight("o/a")
	s.IncrementInFlight("o/b")
	repos := s.AllRepos()
	require.Len(t, repos, 2)
}

func TestConcurrentAcquireRelease(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	const n = 100
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.AcquireSemaphores("o/r", 10, 1000) {
				s.ReleaseSemaphores("o/r")
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 0, s.InFlight("o/r"))
}
