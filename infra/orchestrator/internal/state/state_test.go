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
	s.SetRateLimited(true)
	snap := s.Snapshot()
	require.Equal(t, 3, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["o/a"].InFlight)
	require.Equal(t, 2, snap.PerRepo["o/b"].InFlight)
	require.Equal(t, 10, snap.RateLimitRemaining)
	require.True(t, snap.RateLimited)
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
	require.True(t, s.MarkAssigned("spawn-1", 9001, now.Add(3*time.Second)))
	require.False(t, s.MarkAssigned("spawn-1", 9001, now.Add(4*time.Second)))
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
	require.Equal(t, int64(9001), snap.Reservations["spawn-1"].AssignedJobID)
	require.Zero(t, s.ReconcileDemand("o/r", nil),
		"a fresh snapshot without the assigned job clears its consumed tombstone")

	s.ReleaseReservation("spawn-1")
	s.ReleaseReservation("spawn-1")
	require.Equal(t, 0, s.GlobalInFlight())
	require.Empty(t, s.Snapshot().Reservations)
}

func TestReconcileDemandCountsGenericCapacityAndExactConsumedJobs(t *testing.T) {
	s := New()
	now := time.Now()
	require.Zero(t, s.ReconcileDemand("unknown/repo", []int64{1}))
	require.True(t, s.TryReserve("pending", "o/r", 3, 3, now))
	require.True(t, s.TryReserve("online", "o/r", 3, 3, now))
	require.True(t, s.MarkOnline("online", now))
	require.True(t, s.TryReserve("assigned", "o/r", 3, 3, now))
	require.True(t, s.MarkAssigned("assigned", 11, now))
	require.Equal(t, 3, s.ReconcileDemand("o/r", []int64{11, 12, 13}))
}

func TestReconcileDemandRetainsConsumedJobAcrossCompletionUntilFreshOmission(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	require.True(t, s.TryReserve("completed", "o/r", 3, 3, now))
	require.True(t, s.MarkAssigned("completed", 101, now.Add(time.Second)))
	s.ReleaseReservation("completed")

	require.Equal(t, 1, s.ReconcileDemand("o/r", []int64{101, 202}),
		"a stale queued response for the exact consumed job remains covered after teardown")
	require.Equal(t, 1, s.ReconcileDemand("o/r", []int64{101, 303}),
		"the tombstone must survive repeated stale successful refreshes")
	require.Zero(t, s.ReconcileDemand("o/r", []int64{202}),
		"a successful fresh response clears the absent consumed job")
	require.Zero(t, s.ReconcileDemand("o/r", []int64{101}),
		"a cleared tombstone cannot reappear without a new assignment")
}

func TestReconcileDemandCannotClearActiveAssignmentProtection(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	require.True(t, s.TryReserve("active", "o/r", 3, 3, now))
	require.True(t, s.MarkAssigned("active", 101, now.Add(time.Second)))

	require.Zero(t, s.ReconcileDemand("o/r", nil),
		"a fresh response may omit the active job once it is in progress")
	require.Equal(t, 1, s.ReconcileDemand("o/r", []int64{101}),
		"active assignment identity remains protected from a later stale response")
	s.ReleaseReservation("active")
	require.Equal(t, 1, s.ReconcileDemand("o/r", []int64{101}),
		"release atomically transfers the active identity to a tombstone")
}

func TestReservationCapsAndDirectAssignment(t *testing.T) {
	s := New()
	now := time.Now()
	require.Zero(t, s.InFlight("unknown/repo"))
	require.True(t, s.TryReserve("a", "o/a", 1, 2, now))
	require.False(t, s.TryReserve("b", "o/a", 1, 2, now))
	require.True(t, s.TryReserve("c", "o/b", 2, 2, now))
	require.False(t, s.TryReserve("d", "o/c", 2, 2, now))
	require.True(t, s.MarkAssigned("a", 101, now), "assignment may be observed before a separate online poll")
	require.False(t, s.MarkAssigned("missing", 102, now))
	require.False(t, s.MarkAssigned("c", 0, now), "assignment requires an exact GitHub job ID")
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
				require.True(t, s.MarkAssigned("spawn-1", 9001, now.Add(2*time.Second)))
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

func TestTeardownBlockedTracksOrphanedBackendCapacityDebt(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	require.True(t, s.MarkTeardownBlocked(
		"orphan-spawn", "o/r", "initial teardown failure", now,
	))
	s.UpdateTeardownFailure("orphan-spawn", "network still exists")
	s.UpdateTeardownFailure("unknown-spawn", "must remain a no-op")

	snap := s.Snapshot()
	require.True(t, snap.TeardownBlocked)
	require.True(t, s.SchedulingBlocked())
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["o/r"].InFlight)
	require.Equal(t, 1, snap.PerRepo["o/r"].TeardownBlocked)
	require.Equal(t, int64(1), snap.TeardownFailuresTotal)
	require.Equal(t, SpawnState{
		SpawnID:           "orphan-spawn",
		Repo:              "o/r",
		Phase:             PhaseTeardownBlocked,
		ReservedAt:        now,
		TeardownBlockedAt: now,
		TeardownFailure:   "network still exists",
	}, snap.Reservations["orphan-spawn"])
	require.False(t, s.TryReserve("replacement", "o/r", 2, 2, now))

	require.True(t, s.ResolveTeardown("orphan-spawn"))
	require.False(t, s.SchedulingBlocked())
	require.Zero(t, s.GlobalInFlight())
	require.Equal(t, int64(1), s.Snapshot().TeardownReconciledTotal)
}

func TestResolveTeardownKeepsAdmissionClosedUntilEveryDebtIsReconciled(t *testing.T) {
	s := New()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	require.True(t, s.TryReserve("spawn-1", "o/r", 3, 3, now))
	require.True(t, s.TryReserve("spawn-2", "o/r", 3, 3, now))
	require.False(t, s.ResolveTeardown("spawn-1"), "ordinary reservations are not teardown debt")
	require.True(t, s.MarkTeardownBlocked("spawn-1", "o/r", "network delete failed", now))
	require.True(t, s.MarkTeardownBlocked("spawn-2", "o/r", "proxy delete failed", now))

	require.True(t, s.ResolveTeardown("spawn-1"))
	snap := s.Snapshot()
	require.True(t, snap.TeardownBlocked)
	require.True(t, s.SchedulingBlocked())
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["o/r"].TeardownBlocked)
	require.Contains(t, snap.Reservations, "spawn-2")
	require.Equal(t, int64(2), snap.TeardownFailuresTotal)
	require.Equal(t, int64(1), snap.TeardownReconciledTotal)
	require.False(t, s.TryReserve("replacement", "o/r", 3, 3, now))

	require.True(t, s.ResolveTeardown("spawn-2"))
	snap = s.Snapshot()
	require.False(t, snap.TeardownBlocked)
	require.False(t, s.SchedulingBlocked())
	require.Zero(t, snap.GlobalInFlight)
	require.Equal(t, int64(2), snap.TeardownReconciledTotal)
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

func TestRunnerOperationErrorsAreIndependentAndSnapshotIsolated(t *testing.T) {
	s := New()
	now := time.Now()
	s.RecordPollSuccess("o/r", 1, now)
	s.RecordRunnerOperationFailure(
		"o/r", "generate_jit_config", "github_auth_failed", "status 403",
	)
	s.RecordRunnerOperationFailure(
		"o/r", "delete_runner", "github_auth_failed", "status 401",
	)
	s.RecordPollSuccess("o/r", 0, now.Add(time.Second))

	snap := s.Snapshot()
	require.Empty(t, snap.PerRepo["o/r"].LastPollError)
	require.Len(t, snap.PerRepo["o/r"].RunnerOperationError, 2,
		"successful demand refresh must not mask runner-management auth")
	snap.PerRepo["o/r"].RunnerOperationError["delete_runner"] = OperationError{Class: "mutated"}
	require.Equal(t, "github_auth_failed",
		s.Snapshot().PerRepo["o/r"].RunnerOperationError["delete_runner"].Class,
		"snapshot maps must not alias live state")

	s.RecordRunnerOperationSuccess("o/r", "generate_jit_config")
	snap = s.Snapshot()
	require.NotContains(t, snap.PerRepo["o/r"].RunnerOperationError, "generate_jit_config")
	require.Contains(t, snap.PerRepo["o/r"].RunnerOperationError, "delete_runner")
	s.RecordRunnerOperationSuccess("o/r", "delete_runner")
	require.Empty(t, s.Snapshot().PerRepo["o/r"].RunnerOperationError)
}

func TestEmptyRunnerOperationMapSnapshotIsIsolated(t *testing.T) {
	s := New()
	s.Configure([]string{"o/r"}, 3, 3, "2.1.8", "abcdef")

	snap := s.Snapshot()
	snap.PerRepo["o/r"].RunnerOperationError["get_runner"] = OperationError{
		Class: "mutated",
	}

	require.Empty(t, s.Snapshot().PerRepo["o/r"].RunnerOperationError,
		"even an empty operation map must not alias live readiness state")
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
