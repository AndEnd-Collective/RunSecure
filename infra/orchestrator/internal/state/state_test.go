package state

import (
	"fmt"
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

// --- ETag caching (kube backend runner.yml source) ---

func TestLastETag_UnknownRepo_ReturnsEmpty(t *testing.T) {
	s := New()
	require.Empty(t, s.LastETag("o/r"),
		"LastETag on an unknown repo must return an empty string")
}

func TestSetLastETag_StoresAndRetrieves(t *testing.T) {
	s := New()
	s.SetLastETag("o/r", `"abc123"`)
	require.Equal(t, `"abc123"`, s.LastETag("o/r"))
}

func TestSetLastETag_Overwrites(t *testing.T) {
	s := New()
	s.SetLastETag("o/r", `"v1"`)
	s.SetLastETag("o/r", `"v2"`)
	require.Equal(t, `"v2"`, s.LastETag("o/r"),
		"second SetLastETag must overwrite the first")
}

func TestLastETag_IsolatedPerRepo(t *testing.T) {
	s := New()
	s.SetLastETag("o/a", `"etag-a"`)
	s.SetLastETag("o/b", `"etag-b"`)
	require.Equal(t, `"etag-a"`, s.LastETag("o/a"))
	require.Equal(t, `"etag-b"`, s.LastETag("o/b"))
	require.Empty(t, s.LastETag("o/c"))
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

func TestReservationLifecycleAndSnapshot(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	s.Configure([]string{"o/r"}, 3, 3, "v2.1.8", "abc123")
	require.True(t, s.TryReserve("spawn-1", "o/r", 3, 3, now))
	require.True(t, s.HasReservation("spawn-1", "o/r"))
	require.False(t, s.HasReservation("spawn-1", "other/repo"))
	require.True(t, s.TryReserve("spawn-1", "o/r", 3, 3, now), "same reservation is idempotent")
	require.False(t, s.TryReserve("spawn-1", "other/repo", 3, 3, now))

	s.RecordJIT("spawn-1", 42, "rs-spawn-1-runner")
	require.True(t, s.MarkOnline("spawn-1", now.Add(time.Second)))
	require.False(t, s.MarkOnline("spawn-1", now.Add(2*time.Second)))
	require.True(t, s.MarkAssigned("spawn-1", now.Add(3*time.Second)))
	require.False(t, s.MarkAssigned("spawn-1", now.Add(4*time.Second)))
	s.RecordCompleted()
	s.RecordDeregistered()

	snap := s.Snapshot()
	require.True(t, snap.ConfigLoaded)
	require.Equal(t, 3, snap.ConfiguredCapacity)
	require.Equal(t, 3, snap.WorkerCapacity)
	require.Equal(t, "v2.1.8", snap.Version)
	require.Equal(t, "abc123", snap.BuildSHA)
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 0, snap.PerRepo["o/r"].Pending)
	require.Equal(t, 0, snap.PerRepo["o/r"].Online)
	require.Equal(t, 1, snap.PerRepo["o/r"].Assigned)
	require.Equal(t, int64(1), snap.AssignmentsTotal)
	require.Equal(t, int64(1), snap.CompletedTotal)
	require.Equal(t, int64(1), snap.DeregistrationsTotal)
	require.Equal(t, int64(42), snap.Reservations["spawn-1"].RunnerID)

	s.ReleaseReservation("spawn-1")
	s.ReleaseReservation("spawn-1")
	require.Equal(t, 0, s.GlobalInFlight())
	require.Empty(t, s.Snapshot().Reservations)
}

func TestReservationCapsAndDirectAssignment(t *testing.T) {
	s := New()
	now := time.Now()
	require.Zero(t, s.InFlight("unknown/repo"))
	require.True(t, s.TryReserve("a", "o/a", 1, 2, now))
	require.False(t, s.TryReserve("b", "o/a", 1, 2, now))
	require.True(t, s.TryReserve("c", "o/b", 2, 2, now))
	require.False(t, s.TryReserve("d", "o/c", 2, 2, now))
	require.True(t, s.MarkAssigned("a", now), "busy may be observed before a separate online poll")
	require.False(t, s.MarkAssigned("missing", now))
	require.False(t, s.MarkOnline("missing", now))
	require.Equal(t, 1, s.Snapshot().PerRepo["o/a"].Assigned)
	s.ReleaseReservation("a")
	s.ReleaseReservation("c")
	require.True(t, s.TryReserve("online", "o/c", 1, 1, now))
	require.True(t, s.MarkOnline("online", now))
	s.ReleaseReservation("online")
	require.Zero(t, s.Snapshot().PerRepo["o/c"].Online)
}

func TestTeardownBlockedRetainsCapacityUntilExactResolution(t *testing.T) {
	for _, phase := range []SpawnPhase{PhasePending, PhaseOnline, PhaseAssigned} {
		t.Run(string(phase), func(t *testing.T) {
			s := New()
			now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
			require.True(t, s.TryReserve("spawn-1", "o/r", 2, 2, now))
			if phase == PhaseOnline || phase == PhaseAssigned {
				require.True(t, s.MarkOnline("spawn-1", now.Add(time.Second)))
			}
			if phase == PhaseAssigned {
				require.True(t, s.MarkAssigned("spawn-1", now.Add(2*time.Second)))
			}

			require.True(t, s.MarkTeardownBlocked(
				"spawn-1", "o/r", "network delete failed", now.Add(3*time.Second),
			))
			require.False(t, s.MarkTeardownBlocked(
				"spawn-1", "o/r", "retry still failed", now.Add(4*time.Second),
			))
			s.ReleaseReservation("spawn-1")
			snap := s.Snapshot()
			require.True(t, snap.TeardownBlocked)
			require.True(t, s.SchedulingBlocked())
			require.Equal(t, 1, snap.GlobalInFlight)
			require.Equal(t, 1, snap.PerRepo["o/r"].TeardownBlocked)
			require.Zero(t, snap.PerRepo["o/r"].Pending)
			require.Zero(t, snap.PerRepo["o/r"].Online)
			require.Zero(t, snap.PerRepo["o/r"].Assigned)
			require.Equal(t, "retry still failed", snap.Reservations["spawn-1"].TeardownFailure)
			require.Equal(t, int64(1), snap.TeardownFailuresTotal)
			require.False(t, s.TryReserve("replacement", "o/r", 2, 2, now))

			require.True(t, s.ResolveTeardown("spawn-1"))
			require.False(t, s.ResolveTeardown("spawn-1"))
			snap = s.Snapshot()
			require.False(t, snap.TeardownBlocked)
			require.False(t, s.SchedulingBlocked())
			require.Zero(t, snap.GlobalInFlight)
			require.Zero(t, snap.PerRepo["o/r"].TeardownBlocked)
			require.Equal(t, int64(1), snap.TeardownReconciledTotal)
			require.True(t, s.TryReserve("replacement", "o/r", 2, 2, now))
		})
	}
}

func TestDrainingBlocksAtomicReservation(t *testing.T) {
	s := New()
	s.SetDraining(true)
	require.True(t, s.SchedulingBlocked())
	require.False(t, s.TryReserve("spawn-1", "o/r", 1, 1, time.Now()))
	require.False(t, s.AcquireSemaphores("o/r", 1, 1))
}

func TestPollAndDrainState(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	s.RecordPollAttempt("o/r", now)
	s.RecordPollFailure("o/r", "github_auth_failed", "status 403")
	s.SetBreakerOpen("o/r", true)
	s.SetDraining(true)
	s.RecordUnassignedExit()
	snap := s.Snapshot()
	require.Equal(t, now, snap.PerRepo["o/r"].LastPollAt)
	require.Equal(t, "github_auth_failed", snap.PerRepo["o/r"].LastPollError)
	require.Equal(t, "status 403", snap.PerRepo["o/r"].LastErrorDetail)
	require.True(t, snap.PerRepo["o/r"].BreakerOpen)
	require.True(t, snap.Draining)
	require.Equal(t, int64(1), snap.UnassignedExitsTotal)

	s.RecordPollSuccess("o/r", 4, now.Add(time.Second))
	snap = s.Snapshot()
	require.Equal(t, 4, snap.PerRepo["o/r"].QueuedJobs)
	require.Equal(t, now.Add(time.Second), snap.PerRepo["o/r"].LastPollSuccess)
	require.Empty(t, snap.PerRepo["o/r"].LastPollError)
	require.Empty(t, snap.PerRepo["o/r"].LastErrorDetail)
}

func TestConcurrentReservationsNeverExceedCap(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s.TryReserve(fmt.Sprintf("spawn-%d", id), "o/r", 3, 3, time.Now())
		}(i)
	}
	wg.Wait()
	snap := s.Snapshot()
	require.Equal(t, 3, snap.GlobalInFlight)
	require.Equal(t, 3, snap.PerRepo["o/r"].Pending)
	require.Len(t, snap.Reservations, 3)
}
