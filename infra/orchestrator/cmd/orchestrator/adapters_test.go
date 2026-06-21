package main

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/clock"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/orchestrator"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/server"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

// ============================================================
// envIntOr
// ============================================================

func TestEnvIntOr_Unset_ReturnsFallback(t *testing.T) {
	t.Setenv("__TEST_ENV_INT_OR_UNSET", "")
	got := envIntOr("__TEST_ENV_INT_OR_UNSET", 42)
	require.Equal(t, 42, got, "unset env must return the fallback")
}

func TestEnvIntOr_Set_ReturnsValue(t *testing.T) {
	t.Setenv("__TEST_ENV_INT_OR_SET", "7")
	got := envIntOr("__TEST_ENV_INT_OR_SET", 99)
	require.Equal(t, 7, got, "set env must return the parsed integer")
}

func TestEnvIntOr_Invalid_ReturnsFallback(t *testing.T) {
	t.Setenv("__TEST_ENV_INT_OR_INVALID", "notanumber")
	got := envIntOr("__TEST_ENV_INT_OR_INVALID", 55)
	require.Equal(t, 55, got, "invalid integer string must return the fallback")
}

func TestEnvIntOr_Zero_ReturnsFallback(t *testing.T) {
	// Zero is treated as invalid (n <= 0 guard).
	t.Setenv("__TEST_ENV_INT_OR_ZERO", "0")
	got := envIntOr("__TEST_ENV_INT_OR_ZERO", 33)
	require.Equal(t, 33, got, "zero value must return the fallback (n<=0)")
}

func TestEnvIntOr_Negative_ReturnsFallback(t *testing.T) {
	t.Setenv("__TEST_ENV_INT_OR_NEG", "-5")
	got := envIntOr("__TEST_ENV_INT_OR_NEG", 11)
	require.Equal(t, 11, got, "negative value must return the fallback (n<=0)")
}

func TestEnvIntOr_Large_ReturnsValue(t *testing.T) {
	t.Setenv("__TEST_ENV_INT_OR_LARGE", "3600")
	got := envIntOr("__TEST_ENV_INT_OR_LARGE", 60)
	require.Equal(t, 3600, got, "large positive integer must be parsed and returned")
}

func TestEnvIntOr_KeyAbsent_ReturnsFallback(t *testing.T) {
	os.Unsetenv("__TEST_ENV_INT_OR_ABSENT_KEY_XYZ987")
	got := envIntOr("__TEST_ENV_INT_OR_ABSENT_KEY_XYZ987", 77)
	require.Equal(t, 77, got)
}

// ============================================================
// envOr — complete branch coverage
// ============================================================

func TestEnvOr_Unset_ReturnsFallback(t *testing.T) {
	t.Setenv("__TEST_ENV_OR_KEY_UNSET", "")
	got := envOr("__TEST_ENV_OR_KEY_UNSET", "default")
	require.Equal(t, "default", got)
}

func TestEnvOr_Set_ReturnsValue(t *testing.T) {
	t.Setenv("__TEST_ENV_OR_KEY_SET2", "override")
	got := envOr("__TEST_ENV_OR_KEY_SET2", "default")
	require.Equal(t, "override", got)
}

// ============================================================
// breakerMap
// ============================================================

func TestNewBreakerMap_InitiallyEmpty(t *testing.T) {
	bm := newBreakerMap()
	require.NotNil(t, bm)
	require.Empty(t, bm.breakers, "newly created breakerMap must have no entries")
}

func TestBreakerMap_Get_CreatesOnFirstCall(t *testing.T) {
	bm := newBreakerMap()
	br := bm.get("owner/repo")
	require.NotNil(t, br, "get must create a breaker on first call")
	require.Len(t, bm.breakers, 1)
}

func TestBreakerMap_Get_ReturnsSameInstance(t *testing.T) {
	bm := newBreakerMap()
	br1 := bm.get("owner/repo")
	br2 := bm.get("owner/repo")
	require.Same(t, br1, br2, "get must return the same breaker instance on repeated calls")
}

func TestBreakerMap_Get_DifferentRepos_DifferentBreakers(t *testing.T) {
	bm := newBreakerMap()
	br1 := bm.get("owner/repo1")
	br2 := bm.get("owner/repo2")
	require.NotSame(t, br1, br2, "different repos must have distinct breakers")
	require.Len(t, bm.breakers, 2)
}

func TestBreakerMap_IsOpen_InitiallyClosed(t *testing.T) {
	bm := newBreakerMap()
	require.False(t, bm.IsOpen("owner/repo"), "breaker must start closed")
}

func TestBreakerMap_IsOpen_OpensAfterThresholdFailures(t *testing.T) {
	bm := newBreakerMap()
	// threshold=5 as configured in newBreakerMap.get
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	require.True(t, bm.IsOpen("owner/repo"), "breaker must be open after threshold failures")
}

func TestBreakerMap_MaybeHalfOpen_FalseBeforeCooldown(t *testing.T) {
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	// Cooldown is 5 minutes — hasn't elapsed.
	require.False(t, bm.MaybeHalfOpen("owner/repo"), "MaybeHalfOpen must return false before cooldown")
}

func TestBreakerMap_RecordSuccess_ClosesAfterOpen(t *testing.T) {
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	require.True(t, bm.IsOpen("owner/repo"))

	closed := bm.RecordSuccess("owner/repo")
	require.True(t, closed, "RecordSuccess must return true when transitioning from open→closed")
	require.False(t, bm.IsOpen("owner/repo"), "breaker must be closed after RecordSuccess")
}

func TestBreakerMap_RecordSuccess_AlreadyClosed_ReturnsFalse(t *testing.T) {
	bm := newBreakerMap()
	closed := bm.RecordSuccess("owner/repo")
	require.False(t, closed, "RecordSuccess on an already-closed breaker must return false")
}

func TestBreakerMap_RecordFailure_ReturnsOpenAndCount(t *testing.T) {
	bm := newBreakerMap()
	// First failure: not yet opened, count=1.
	opened, count := bm.RecordFailure("owner/repo")
	require.False(t, opened, "first failure must not open breaker (threshold=5)")
	require.Equal(t, 1, count)

	// Add three more (total 4) — still not opened.
	for i := 0; i < 3; i++ {
		bm.RecordFailure("owner/repo")
	}
	// 5th failure triggers open.
	opened, count = bm.RecordFailure("owner/repo")
	require.True(t, opened, "fifth failure must open the breaker")
	require.Equal(t, 5, count)
}

func TestBreakerMap_Snapshot_Empty(t *testing.T) {
	bm := newBreakerMap()
	snap := bm.snapshot()
	require.NotNil(t, snap)
	require.Empty(t, snap, "snapshot of empty map must be empty")
}

func TestBreakerMap_Snapshot_ReflectsOpenState(t *testing.T) {
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	snap := bm.snapshot()
	require.Len(t, snap, 1)
	require.True(t, snap["owner/repo"], "snapshot must mark breaker as open")
}

func TestBreakerMap_Snapshot_ReflectsClosedState(t *testing.T) {
	bm := newBreakerMap()
	bm.RecordFailure("owner/repo") // 1 failure, threshold=5 → still closed
	snap := bm.snapshot()
	require.Len(t, snap, 1)
	require.False(t, snap["owner/repo"], "snapshot must mark non-open breaker as false")
}

func TestBreakerMap_Snapshot_MultipleRepos(t *testing.T) {
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/a")
	}
	bm.RecordFailure("owner/b") // creates entry, stays closed

	snap := bm.snapshot()
	require.Len(t, snap, 2)
	require.True(t, snap["owner/a"])
	require.False(t, snap["owner/b"])
}

func TestBreakerMap_Snapshot_IncludesAllRepos(t *testing.T) {
	bm := newBreakerMap()
	repos := []string{"owner/a", "owner/b", "owner/c"}
	for _, r := range repos {
		bm.RecordFailure(r)
	}
	snap := bm.snapshot()
	require.Len(t, snap, 3)
	for _, r := range repos {
		_, ok := snap[r]
		require.True(t, ok, "snapshot must include %s", r)
	}
}

func TestBreakerMap_Concurrent_Safe(t *testing.T) {
	bm := newBreakerMap()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			repo := fmt.Sprintf("owner/repo%d", n%5)
			bm.RecordFailure(repo)
			bm.IsOpen(repo)
			bm.MaybeHalfOpen(repo)
			bm.RecordSuccess(repo)
			bm.snapshot()
		}(i)
	}
	wg.Wait()
}

func TestBreakerMap_IsOpen_ClosedAfterRecordSuccess(t *testing.T) {
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	require.True(t, bm.IsOpen("owner/repo"))
	bm.RecordSuccess("owner/repo")
	require.False(t, bm.IsOpen("owner/repo"))
}

func TestBreakerMap_RecordFailure_HalfOpenGoesToOpen(t *testing.T) {
	// Use a breaker with a very short cooldown to reach HalfOpen.
	bm := &breakerMap{breakers: map[string]*state.Breaker{}}
	br := state.NewBreaker(1, time.Millisecond, time.Now)
	bm.breakers["owner/repo"] = br

	// threshold=1: first failure opens.
	opened, count := bm.RecordFailure("owner/repo")
	require.True(t, opened, "first failure must open breaker with threshold=1")
	require.Equal(t, 1, count)

	// Wait for cooldown, transition to HalfOpen.
	time.Sleep(5 * time.Millisecond)
	transitioned := bm.MaybeHalfOpen("owner/repo")
	require.True(t, transitioned, "MaybeHalfOpen must return true after cooldown")

	// Failure while HalfOpen must re-open.
	opened2, _ := bm.RecordFailure("owner/repo")
	require.True(t, opened2, "failure in HalfOpen must re-open breaker")
	require.True(t, bm.IsOpen("owner/repo"))
}

func TestBreakerMap_RecordSuccess_OnClosedBreaker_ReturnsFalse(t *testing.T) {
	bm := newBreakerMap()
	bm.RecordFailure("owner/repo") // 1 failure, threshold=5
	closed := bm.RecordSuccess("owner/repo")
	require.False(t, closed, "RecordSuccess on a closed breaker must return false")
}

// ============================================================
// newServerDeps + serverDeps methods
// ============================================================

func TestNewServerDeps_InitializesFields(t *testing.T) {
	st := state.New()
	clk := clock.System()
	before := time.Now()
	sd := newServerDeps(st, clk, 30)
	after := time.Now()

	require.NotNil(t, sd)
	require.Equal(t, 30, sd.PollIntervalSeconds())

	lp := sd.LastPollAt()
	require.False(t, lp.Before(before), "lastPoll must be >= before")
	require.False(t, lp.After(after), "lastPoll must be <= after")
}

func TestServerDeps_Now_MatchesClock(t *testing.T) {
	st := state.New()
	fixed := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(fixed)
	sd := newServerDeps(st, clk, 10)
	require.Equal(t, fixed, sd.Now(), "Now must delegate to the injected clock")
}

func TestServerDeps_PollIntervalSeconds_Returned(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 120)
	require.Equal(t, 120, sd.PollIntervalSeconds())
}

func TestServerDeps_LastPollAt_NilPointerSafe(t *testing.T) {
	sd := &serverDeps{}
	sd.lastPoll.Store(nil)
	got := sd.LastPollAt()
	require.True(t, got.IsZero(), "nil pointer must return zero time")
}

func TestServerDeps_LastPollAt_ReturnsStoredValue(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	expected := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	sd.lastPoll.Store(&expected)
	require.Equal(t, expected, sd.LastPollAt())
}

func TestServerDeps_StateSnapshot_DelegatesToState(t *testing.T) {
	st := state.New()
	st.IncrementInFlight("owner/repo")
	sd := newServerDeps(st, clock.System(), 10)
	snap := sd.StateSnapshot()
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["owner/repo"].InFlight)
}

func TestServerDeps_StateSnapshot_EmptyState(t *testing.T) {
	st := state.New()
	sd := newServerDeps(st, clock.System(), 10)
	snap := sd.StateSnapshot()
	require.Equal(t, 0, snap.GlobalInFlight)
	require.Empty(t, snap.PerRepo)
}

func TestServerDeps_StateSnapshot_AfterModification(t *testing.T) {
	st := state.New()
	st.IncrementInFlight("owner/a")
	st.IncrementInFlight("owner/a")
	st.DecrementInFlight("owner/a")
	sd := newServerDeps(st, clock.System(), 10)
	snap := sd.StateSnapshot()
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["owner/a"].InFlight)
}

func TestServerDeps_APICalls_EmptyWhenNoEntries(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	calls := sd.APICalls()
	require.NotNil(t, calls)
	require.Empty(t, calls)
}

func TestServerDeps_APICalls_ReturnsStoredValues(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	var n int64 = 7
	key := server.APICallKey{Endpoint: "/repos", Status: "200"}
	sd.api.Store(key, &n)
	calls := sd.APICalls()
	require.Len(t, calls, 1)
	require.Equal(t, int64(7), calls[key])
}

func TestServerDeps_APICalls_MultipleEntries(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	var n1, n2 int64 = 5, 9
	k1 := server.APICallKey{Endpoint: "/queue", Status: "200"}
	k2 := server.APICallKey{Endpoint: "/jit", Status: "201"}
	sd.api.Store(k1, &n1)
	sd.api.Store(k2, &n2)
	calls := sd.APICalls()
	require.Equal(t, int64(5), calls[k1])
	require.Equal(t, int64(9), calls[k2])
}

func TestServerDeps_APICalls_ConcurrentSafe(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var v int64 = int64(n)
			k := server.APICallKey{Endpoint: fmt.Sprintf("/ep%d", n), Status: "200"}
			sd.api.Store(k, &v)
			_ = sd.APICalls()
		}(i)
	}
	wg.Wait()
}

func TestServerDeps_SpawnsTotal_EmptyWhenNoEntries(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	spawns := sd.SpawnsTotal()
	require.NotNil(t, spawns)
	require.Empty(t, spawns)
}

func TestServerDeps_SpawnsTotal_ReturnsStoredValues(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	var n int64 = 3
	key := server.SpawnKey{Scope: "s", Repo: "r", Outcome: "ok"}
	sd.spawns.Store(key, &n)
	spawns := sd.SpawnsTotal()
	require.Len(t, spawns, 1)
	require.Equal(t, int64(3), spawns[key])
}

func TestServerDeps_SpawnsTotal_MultipleEntries(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	var n1, n2 int64 = 2, 8
	k1 := server.SpawnKey{Scope: "s1", Repo: "r1", Outcome: "ok"}
	k2 := server.SpawnKey{Scope: "s1", Repo: "r2", Outcome: "err"}
	sd.spawns.Store(k1, &n1)
	sd.spawns.Store(k2, &n2)
	spawns := sd.SpawnsTotal()
	require.Equal(t, int64(2), spawns[k1])
	require.Equal(t, int64(8), spawns[k2])
}

func TestServerDeps_SpawnDurations_ReturnsNil(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	require.Nil(t, sd.SpawnDurations())
}

func TestServerDeps_BreakerOpen_NilSnap_ReturnsNil(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	// breakerSnap is nil by default.
	require.Nil(t, sd.BreakerOpen(), "nil breakerSnap must return nil")
}

func TestServerDeps_BreakerOpen_DelegatesToSnap(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	bm := newBreakerMap()
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	sd.breakerSnap = bm.snapshot

	got := sd.BreakerOpen()
	require.Len(t, got, 1)
	require.True(t, got["owner/repo"])
}

func TestServerDeps_BreakerOpen_AllClosed(t *testing.T) {
	bm := newBreakerMap()
	for _, r := range []string{"a", "b", "c"} {
		bm.RecordFailure(r) // 1 failure each, threshold=5 → closed
	}
	sd := newServerDeps(state.New(), clock.System(), 10)
	sd.breakerSnap = bm.snapshot

	got := sd.BreakerOpen()
	for _, v := range got {
		require.False(t, v, "all breakers must be closed")
	}
}

func TestServerDeps_Now_NonZero(t *testing.T) {
	sd := newServerDeps(state.New(), clock.System(), 10)
	require.False(t, sd.Now().IsZero(), "Now() must return a non-zero time")
}

func TestNewServerDeps_LastPollAt_StoredSnapshot(t *testing.T) {
	st := state.New()
	before := time.Now()
	sd := newServerDeps(st, clock.System(), 10)
	after := time.Now()

	lp := sd.LastPollAt()
	require.False(t, lp.Before(before))
	require.False(t, lp.After(after))
}

// ============================================================
// productionDeps accessors
// ============================================================

func makeProdDeps(t *testing.T) *productionDeps {
	t.Helper()
	st := state.New()
	clk := clock.System()
	sd := newServerDeps(st, clk, 30)
	bm := newBreakerMap()
	em := cornerstone.NewEmitter(os.Stdout, cornerstone.SystemClock, cornerstone.SystemUUID)
	dc, err := docker.NewClient("tcp://127.0.0.1:9999")
	require.NoError(t, err)
	rl := state.NewTokenBucket(5, 10, time.Now)

	scope := &config.Scope{
		Name:             "test-scope",
		GlobalMaxRunners: 10,
		Repos: []config.RepoBlock{
			{Repo: "owner/repo", MaxConcurrent: 3},
			{Repo: "owner/repo2", MaxConcurrent: 2},
		},
	}
	return &productionDeps{
		dc:         dc,
		em:         em,
		clk:        clk,
		st:         st,
		eg:         nil,
		bucket:     rl,
		brks:       bm,
		intents:    make(chan orchestrator.SpawnIntent, 8),
		scopeRef:   scope,
		serverDeps: sd,
	}
}

func TestProductionDeps_Docker_ReturnsClient(t *testing.T) {
	dc, err := docker.NewClient("tcp://127.0.0.1:9999")
	require.NoError(t, err)
	pd := &productionDeps{dc: dc}
	require.Equal(t, dc, pd.Docker())
}

func TestProductionDeps_Emit_ReturnsEmitter(t *testing.T) {
	em := cornerstone.NewEmitter(os.Stdout, cornerstone.SystemClock, cornerstone.SystemUUID)
	pd := &productionDeps{em: em}
	require.Same(t, em, pd.Emit())
}

func TestProductionDeps_Clock_ReturnsClock(t *testing.T) {
	clk := clock.System()
	pd := &productionDeps{clk: clk}
	require.Equal(t, clk, pd.Clock())
}

func TestProductionDeps_State_ReturnsState(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}
	require.Equal(t, st, pd.State())
}

func TestProductionDeps_GitHub_Nil_WhenNotSet(t *testing.T) {
	pd := &productionDeps{gh: nil}
	require.Nil(t, pd.GitHub())
}

func TestProductionDeps_GitHub_ReturnsClient(t *testing.T) {
	dir := t.TempDir()
	patFile := dir + "/pat"
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))
	gh, err := github.NewClient("http://localhost:9999", patFile)
	require.NoError(t, err)
	pd := &productionDeps{gh: gh}
	require.Same(t, gh, pd.GitHub())
}

func TestProductionDeps_InFlight_DelegatesToState(t *testing.T) {
	st := state.New()
	st.IncrementInFlight("owner/repo")
	st.IncrementInFlight("owner/repo")
	pd := &productionDeps{st: st}
	require.Equal(t, 2, pd.InFlight("owner/repo"))
	require.Equal(t, 0, pd.InFlight("owner/other"))
}

func TestProductionDeps_GlobalInFlight_DelegatesToState(t *testing.T) {
	st := state.New()
	st.IncrementInFlight("owner/a")
	st.IncrementInFlight("owner/b")
	pd := &productionDeps{st: st}
	require.Equal(t, 2, pd.GlobalInFlight())
}

func TestProductionDeps_BreakerIsOpen_DelegatesToBreakerMap(t *testing.T) {
	bm := newBreakerMap()
	pd := &productionDeps{brks: bm}
	require.False(t, pd.BreakerIsOpen("owner/repo"))
	for i := 0; i < 5; i++ {
		bm.RecordFailure("owner/repo")
	}
	require.True(t, pd.BreakerIsOpen("owner/repo"))
}

func TestProductionDeps_BreakerMaybeHalfOpen_Delegates(t *testing.T) {
	bm := newBreakerMap()
	pd := &productionDeps{brks: bm}
	// Closed breaker: MaybeHalfOpen returns false.
	require.False(t, pd.BreakerMaybeHalfOpen("owner/repo"))
}

func TestProductionDeps_NewSpawnID_Unique(t *testing.T) {
	pd := &productionDeps{}
	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id := pd.NewSpawnID()
		require.NotEmpty(t, id)
		_, dup := ids[id]
		require.False(t, dup, "NewSpawnID must return unique IDs")
		ids[id] = struct{}{}
	}
}

func TestProductionDeps_NewSpawnID_ContainsOnlyDigits(t *testing.T) {
	pd := &productionDeps{}
	for i := 0; i < 20; i++ {
		id := pd.NewSpawnID()
		for _, c := range id {
			require.True(t, c >= '0' && c <= '9',
				"NewSpawnID must contain only digits; got %q in %q", c, id)
		}
	}
}

func TestProductionDeps_NewSpawnID_Concurrent_AllUnique(t *testing.T) {
	pd := &productionDeps{}
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := pd.NewSpawnID()
			mu.Lock()
			seen[id] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Len(t, seen, 200, "NewSpawnID must produce 200 unique values concurrently")
}

func TestProductionDeps_RecordPollTick_UpdatesServerDeps(t *testing.T) {
	st := state.New()
	sd := newServerDeps(st, clock.System(), 10)
	// Set lastPoll to the past.
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	sd.lastPoll.Store(&past)

	pd := &productionDeps{serverDeps: sd}
	before := time.Now()
	pd.RecordPollTick()
	after := time.Now()

	lp := sd.LastPollAt()
	require.False(t, lp.Before(before), "lastPoll must be updated to now")
	require.False(t, lp.After(after), "lastPoll must not be in the future")
}

func TestProductionDeps_RecordPollTick_Concurrent(t *testing.T) {
	st := state.New()
	sd := newServerDeps(st, clock.System(), 10)
	pd := &productionDeps{serverDeps: sd}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pd.RecordPollTick()
		}()
	}
	wg.Wait()
	require.False(t, sd.LastPollAt().IsZero())
}

func TestProductionDeps_GlobalMaxRunners_FromScope(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{GlobalMaxRunners: 25},
	}
	require.Equal(t, 25, pd.GlobalMaxRunners())
}

func TestProductionDeps_RepoMaxConcurrent_KnownRepo(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{
				{Repo: "owner/repo", MaxConcurrent: 7},
			},
		},
	}
	require.Equal(t, 7, pd.RepoMaxConcurrent("owner/repo"))
}

func TestProductionDeps_RepoMaxConcurrent_UnknownRepo_DefaultsToOne(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{
				{Repo: "owner/repo", MaxConcurrent: 7},
			},
		},
	}
	require.Equal(t, 1, pd.RepoMaxConcurrent("owner/unknown"))
}

func TestProductionDeps_RepoMaxConcurrent_MultipleRepos(t *testing.T) {
	repos := make([]config.RepoBlock, 10)
	for i := range repos {
		repos[i] = config.RepoBlock{
			Repo:          fmt.Sprintf("owner/repo%d", i),
			MaxConcurrent: i + 1,
		}
	}
	pd := &productionDeps{
		scopeRef: &config.Scope{Repos: repos},
	}
	for i, r := range repos {
		require.Equal(t, i+1, pd.RepoMaxConcurrent(r.Repo))
	}
}

func TestProductionDeps_ScopeName_FromScope(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{Name: "my-scope"},
	}
	require.Equal(t, "my-scope", pd.ScopeName())
}

func TestProductionDeps_ProxyImageDigest_FromEnv(t *testing.T) {
	t.Setenv("RUNSECURE_PROXY_IMAGE", "ghcr.io/example/proxy@sha256:abc123")
	pd := &productionDeps{}
	require.Equal(t, "ghcr.io/example/proxy@sha256:abc123", pd.ProxyImageDigest())
}

func TestProductionDeps_ProxyImageDigest_Unset_ReturnsEmpty(t *testing.T) {
	t.Setenv("RUNSECURE_PROXY_IMAGE", "")
	pd := &productionDeps{}
	require.Empty(t, pd.ProxyImageDigest())
}

func TestProductionDeps_RunnerImageDigestFor_RuntimeSpecific(t *testing.T) {
	t.Setenv("RUNSECURE_RUNNER_IMAGE_NODE", "ghcr.io/example/runner-node@sha256:def456")
	t.Setenv("RUNSECURE_RUNNER_IMAGE_DEFAULT", "")
	pd := &productionDeps{}
	require.Equal(t, "ghcr.io/example/runner-node@sha256:def456", pd.RunnerImageDigestFor("node"))
}

func TestProductionDeps_RunnerImageDigestFor_RuntimeWithColon(t *testing.T) {
	// "node:24" → env var RUNSECURE_RUNNER_IMAGE_NODE
	t.Setenv("RUNSECURE_RUNNER_IMAGE_NODE", "img@sha256:aaa")
	t.Setenv("RUNSECURE_RUNNER_IMAGE_DEFAULT", "")
	pd := &productionDeps{}
	require.Equal(t, "img@sha256:aaa", pd.RunnerImageDigestFor("node:24"))
}

func TestProductionDeps_RunnerImageDigestFor_FallsBackToDefault(t *testing.T) {
	t.Setenv("RUNSECURE_RUNNER_IMAGE_PYTHON", "")
	t.Setenv("RUNSECURE_RUNNER_IMAGE_DEFAULT", "ghcr.io/example/runner-default@sha256:111")
	pd := &productionDeps{}
	require.Equal(t, "ghcr.io/example/runner-default@sha256:111", pd.RunnerImageDigestFor("python"))
}

func TestProductionDeps_RunnerImageDigestFor_BothUnset_ReturnsEmpty(t *testing.T) {
	t.Setenv("RUNSECURE_RUNNER_IMAGE_RUST", "")
	t.Setenv("RUNSECURE_RUNNER_IMAGE_DEFAULT", "")
	pd := &productionDeps{}
	require.Empty(t, pd.RunnerImageDigestFor("rust"))
}

func TestProductionDeps_SeccompProfileHostPath_Empty_ReturnsEmpty(t *testing.T) {
	pd := &productionDeps{}
	require.Empty(t, pd.SeccompProfileHostPath(""))
}

func TestProductionDeps_SeccompProfileHostPath_Named_ReturnsPath(t *testing.T) {
	pd := &productionDeps{}
	got := pd.SeccompProfileHostPath("node-runner.json")
	require.Equal(t, "/host/seccomp/node-runner.json", got)
}

func TestProductionDeps_RateLimiter_TryTake(t *testing.T) {
	bucket := state.NewTokenBucket(100, 10, time.Now)
	pd := &productionDeps{bucket: bucket}
	rl := pd.RateLimiter()
	require.True(t, rl.TryTake(), "token bucket with tokens available must return true")
}

func TestProductionDeps_Breakers_ReturnsBreakers(t *testing.T) {
	bm := newBreakerMap()
	pd := &productionDeps{brks: bm}
	got := pd.Breakers()
	require.NotNil(t, got)
}

func TestProductionDeps_Egress_ReturnsNonNil(t *testing.T) {
	pd := &productionDeps{eg: nil, allowKeys: nil}
	e := pd.Egress()
	require.NotNil(t, e, "Egress() must return a non-nil EgressGenerator")
}

func TestProductionDeps_IntentChannel_NotNil(t *testing.T) {
	ch := make(chan orchestrator.SpawnIntent, 4)
	pd := &productionDeps{intents: ch}
	got := pd.IntentChannel()
	require.NotNil(t, got)
	require.Equal(t, 4, cap(ch))
}

// ============================================================
// RateLimit methods on productionDeps
// ============================================================

func TestProductionDeps_RateLimitContextFor_ZeroReset_EmptyResetStr(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}
	rem, lim, resetStr := pd.RateLimitContextFor("owner/repo")
	require.Equal(t, 0, rem)
	require.Equal(t, 0, lim)
	require.Empty(t, resetStr, "zero reset time must produce empty reset string")
}

func TestProductionDeps_RateLimitContextFor_NonZeroReset_FormatsRFC3339(t *testing.T) {
	st := state.New()
	reset := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	st.SetRateLimit(4500, 5000, reset)
	pd := &productionDeps{st: st}

	rem, lim, resetStr := pd.RateLimitContextFor("owner/repo")
	require.Equal(t, 4500, rem)
	require.Equal(t, 5000, lim)
	require.Equal(t, reset.Format(time.RFC3339), resetStr)
}

func TestProductionDeps_RateLimitContextFor_RepoArgIgnored(t *testing.T) {
	st := state.New()
	reset := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	st.SetRateLimit(100, 5000, reset)
	pd := &productionDeps{st: st}

	rem1, lim1, _ := pd.RateLimitContextFor("owner/repo1")
	rem2, lim2, _ := pd.RateLimitContextFor("owner/repo2")
	require.Equal(t, rem1, rem2, "RateLimitContextFor is per-scope; repo arg is ignored")
	require.Equal(t, lim1, lim2)
}

func TestProductionDeps_RecordRateLimit_PersistsToState(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}
	rl := github.RateLimit{Remaining: 3000, Limit: 5000, ResetUnix: 1700000000}
	pd.RecordRateLimit("owner/repo", rl)

	rem, lim, reset := st.RateLimit()
	require.Equal(t, 3000, rem)
	require.Equal(t, 5000, lim)
	require.Equal(t, time.Unix(1700000000, 0), reset)
}

func TestProductionDeps_RecordRateLimit_ZeroValues(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}
	pd.RecordRateLimit("owner/repo", github.RateLimit{Remaining: 0, Limit: 0, ResetUnix: 0})

	rem, lim, reset := st.RateLimit()
	require.Equal(t, 0, rem)
	require.Equal(t, 0, lim)
	require.Equal(t, time.Unix(0, 0), reset)
}

func TestProductionDeps_MarkRateLimited_SetsFlag(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}

	require.False(t, pd.IsRateLimited("owner/repo"))
	pd.MarkRateLimited("owner/repo")
	require.True(t, pd.IsRateLimited("owner/repo"))
}

func TestProductionDeps_MarkRateLimited_UsesStateResetWhenSet(t *testing.T) {
	st := state.New()
	reset := time.Now().Add(2 * time.Minute)
	st.SetRateLimit(0, 5000, reset)

	pd := &productionDeps{st: st}
	pd.MarkRateLimited("owner/repo")

	pd.rlMu.Lock()
	storedReset := pd.rlReset
	pd.rlMu.Unlock()

	diff := storedReset.Sub(reset)
	if diff < 0 {
		diff = -diff
	}
	require.Less(t, diff, time.Second, "rlReset must match state.RateLimit reset")
}

func TestProductionDeps_MarkRateLimited_FallbackResetWhenStateZero(t *testing.T) {
	st := state.New() // rlReset is zero
	pd := &productionDeps{st: st}

	before := time.Now()
	pd.MarkRateLimited("owner/repo")
	after := time.Now()

	pd.rlMu.Lock()
	storedReset := pd.rlReset
	pd.rlMu.Unlock()

	minExpected := before.Add(time.Minute)
	maxExpected := after.Add(time.Minute)
	require.False(t, storedReset.Before(minExpected), "fallback reset must be >= now+1min")
	require.False(t, storedReset.After(maxExpected), "fallback reset must be <= after+1min")
}

func TestProductionDeps_IsRateLimited_FalseInitially(t *testing.T) {
	pd := &productionDeps{st: state.New()}
	require.False(t, pd.IsRateLimited("owner/repo"))
}

func TestProductionDeps_MaybeClearRateLimit_ClearsAfterExpiry(t *testing.T) {
	st := state.New()
	pd := &productionDeps{st: st}

	pd.rlMu.Lock()
	pd.rlPaused = true
	pd.rlReset = time.Now().Add(-time.Millisecond)
	pd.rlMu.Unlock()

	cleared := pd.MaybeClearRateLimit("owner/repo")
	require.True(t, cleared, "MaybeClearRateLimit must return true when reset has elapsed")
	require.False(t, pd.IsRateLimited("owner/repo"))
}

func TestProductionDeps_MaybeClearRateLimit_RetainedBeforeExpiry(t *testing.T) {
	pd := &productionDeps{st: state.New()}
	pd.rlMu.Lock()
	pd.rlPaused = true
	pd.rlReset = time.Now().Add(10 * time.Minute)
	pd.rlMu.Unlock()

	cleared := pd.MaybeClearRateLimit("owner/repo")
	require.False(t, cleared, "MaybeClearRateLimit must return false before reset")
	require.True(t, pd.IsRateLimited("owner/repo"))
}

func TestProductionDeps_MaybeClearRateLimit_NotPaused_ReturnsFalse(t *testing.T) {
	pd := &productionDeps{st: state.New()}
	cleared := pd.MaybeClearRateLimit("owner/repo")
	require.False(t, cleared)
}

// ============================================================
// tokenBucketAdapter
// ============================================================

func TestTokenBucketAdapter_TryTake_WithTokens_ReturnsTrue(t *testing.T) {
	b := state.NewTokenBucket(100, 10, time.Now)
	a := tokenBucketAdapter{b: b}
	require.True(t, a.TryTake(), "adapter must delegate TryTake to the underlying bucket")
}

func TestTokenBucketAdapter_TryTake_NoTokens_ReturnsFalse(t *testing.T) {
	b := state.NewTokenBucket(0.001, 1, time.Now)
	b.TryTake() // drain the single token
	a := tokenBucketAdapter{b: b}
	require.False(t, a.TryTake(), "empty bucket must return false")
}

// ============================================================
// upperRuntime
// ============================================================

func TestUpperRuntime_AllCases(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"node", "NODE"},
		{"node:24", "NODE"},
		{"python:3.12", "PYTHON"},
		{"rust:stable", "RUST"},
		{"JAVA", "JAVA"},
		{"go/1.21", "GO"},
		{":tag", ""},
		{"/path", ""},
		{"runner-node", "RUNNER-NODE"},
		{"node24", "NODE24"},
		{"Python", "PYTHON"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := upperRuntime(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestUpperRuntime_OnlyColon_ReturnsEmpty(t *testing.T) {
	require.Equal(t, "", upperRuntime(":"))
}

func TestUpperRuntime_OnlySlash_ReturnsEmpty(t *testing.T) {
	require.Equal(t, "", upperRuntime("/"))
}

// ============================================================
// nextSeq
// ============================================================

func TestNextSeq_Monotonic(t *testing.T) {
	a := nextSeq()
	b := nextSeq()
	c := nextSeq()
	require.Less(t, a, b, "nextSeq must be strictly increasing")
	require.Less(t, b, c)
}

func TestNextSeq_Concurrent_AllUnique(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[int64]struct{})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := nextSeq()
			mu.Lock()
			seen[v] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Len(t, seen, 200, "nextSeq must produce unique values under concurrency")
}

// ============================================================
// filepath_join
// ============================================================

func TestFilepathJoin_Empty(t *testing.T) {
	require.Equal(t, "", filepath_join())
}

func TestFilepathJoin_SinglePart(t *testing.T) {
	require.Equal(t, "/foo", filepath_join("/foo"))
}

func TestFilepathJoin_MultipleParts(t *testing.T) {
	require.Equal(t, "/a/b/c", filepath_join("/a", "b", "c"))
}

// ============================================================
// productionDeps.RunnerYML — unknown repo in compose path
// ============================================================

func TestProductionDeps_RunnerYML_UnknownRepo_Compose_ReturnsError(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{{Repo: "owner/repo"}},
		},
	}
	_, err := pd.RunnerYML("owner/unknown")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown repo")
}

// ============================================================
// productionDeps.RunnerYML — parse error and egress validation error paths
// ============================================================

func TestProductionDeps_RunnerYML_ParseError_ReturnsError(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{{Repo: "owner/repo", ProjectDir: "/nonexistent/dir/xyz"}},
		},
	}
	_, err := pd.RunnerYML("owner/repo")
	require.Error(t, err, "missing runner.yml must return an error")
}

func TestProductionDeps_RunnerYML_EgressValidationError_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	ghDir := dir + "/.github"
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	// Duplicate TCP port triggers egress validation error.
	require.NoError(t, os.WriteFile(ghDir+"/runner.yml", []byte(`
runtime: node:24
tcp_egress:
  - db.example.com:5432
  - other.example.com:5432
`), 0o644))

	pd := &productionDeps{
		scopeRef: &config.Scope{
			Repos: []config.RepoBlock{{Repo: "owner/repo", ProjectDir: dir}},
		},
	}
	_, err := pd.RunnerYML("owner/repo")
	require.Error(t, err)
	require.Contains(t, err.Error(), "egress")
}

// ============================================================
// envIntOr — Sscanf edge cases
// ============================================================

func TestEnvIntOr_FloatString_ParsesIntPart(t *testing.T) {
	// fmt.Sscanf("%d") stops at '.', reading 1 which is > 0.
	t.Setenv("__TEST_ENV_INT_OR_FLOAT", "1.5")
	got := envIntOr("__TEST_ENV_INT_OR_FLOAT", 99)
	// Sscanf parses "1" successfully (stops at "."), n=1 > 0.
	require.Equal(t, 1, got)
}

func TestEnvIntOr_TrailingText_ReturnsIntPart(t *testing.T) {
	// "10abc" — Sscanf with %d parses "10" and ignores the rest.
	t.Setenv("__TEST_ENV_INT_OR_TRAIL", "10abc")
	got := envIntOr("__TEST_ENV_INT_OR_TRAIL", 99)
	require.Equal(t, 10, got)
}
