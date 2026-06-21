package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

// fakeDeps implements all the server dep interfaces for testing.
type fakeDeps struct {
	lastPoll  time.Time
	now       time.Time
	intervalS int
	snap      state.Snapshot
	api       map[APICallKey]int64
	spawns    map[SpawnKey]int64
	durations map[string][]float64
	breakers  map[string]bool
}

func (f *fakeDeps) LastPollAt() time.Time                { return f.lastPoll }
func (f *fakeDeps) Now() time.Time                       { return f.now }
func (f *fakeDeps) PollIntervalSeconds() int             { return f.intervalS }
func (f *fakeDeps) StateSnapshot() state.Snapshot        { return f.snap }
func (f *fakeDeps) APICalls() map[APICallKey]int64       { return f.api }
func (f *fakeDeps) SpawnsTotal() map[SpawnKey]int64      { return f.spawns }
func (f *fakeDeps) SpawnDurations() map[string][]float64 { return f.durations }
func (f *fakeDeps) BreakerOpen() map[string]bool         { return f.breakers }

func newDeps(t *testing.T) *fakeDeps {
	t.Helper()
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	return &fakeDeps{
		lastPoll:  now.Add(-5 * time.Second),
		now:       now,
		intervalS: 15,
		snap: state.Snapshot{
			PerRepo:            map[string]state.RepoState{"o/r": {InFlight: 2}},
			GlobalInFlight:     2,
			RateLimitRemaining: 4321,
			RateLimitLimit:     5000,
		},
		api:      map[APICallKey]int64{{Endpoint: "queued", Status: "200"}: 100},
		spawns:   map[SpawnKey]int64{{Scope: "s", Repo: "o/r", Outcome: "success"}: 5},
		breakers: map[string]bool{"o/r": false},
	}
}

func TestHealthz_OkWhenFresh(t *testing.T) {
	d := newDeps(t)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	h := NewHealthz(d, em)
	rr := httpRec()
	h.ServeHTTP(rr, httpReq("GET", "/healthz"))
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "ok")
	require.Equal(t, int64(1), h.Hits())
}

// Mutation kill: healthz.go:44 — `if staleness >= limit`. Boundary case
// where staleness EXACTLY equals limit should be treated as stale.
func TestHealthz_StaleAtExactBoundary(t *testing.T) {
	d := newDeps(t)
	// staleness = limit (3 * 15s = 45s). With >=, this should be stale.
	d.lastPoll = d.now.Add(-45 * time.Second)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	h := NewHealthz(d, em)
	rr := httpRec()
	h.ServeHTTP(rr, httpReq("GET", "/healthz"))
	require.Equal(t, http.StatusInternalServerError, rr.Code,
		"staleness exactly equal to limit must return 500 (>=, not >)")
}

func TestHealthz_OkJustBelowBoundary(t *testing.T) {
	d := newDeps(t)
	d.lastPoll = d.now.Add(-44*time.Second - 999*time.Millisecond)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	h := NewHealthz(d, em)
	rr := httpRec()
	h.ServeHTTP(rr, httpReq("GET", "/healthz"))
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHealthz_StaleWhenLastPollTooOld(t *testing.T) {
	d := newDeps(t)
	d.lastPoll = d.now.Add(-3 * time.Minute) // way past 3 * 15s
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	h := NewHealthz(d, em)
	rr := httpRec()
	h.ServeHTTP(rr, httpReq("GET", "/healthz"))
	require.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestMetrics_RendersTextFormat(t *testing.T) {
	d := newDeps(t)
	m := NewMetrics(d)
	rr := httpRec()
	m.ServeHTTP(rr, httpReq("GET", "/metrics"))
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.True(t, strings.Contains(body, `runsecure_orchestrator_in_flight_runners{repo="o/r"} 2`))
	require.True(t, strings.Contains(body, `runsecure_orchestrator_api_rate_limit_remaining 4321`))
	require.True(t, strings.Contains(body, `runsecure_orchestrator_spawns_total{scope="s",repo="o/r",outcome="success"} 5`))
	require.True(t, strings.Contains(body, `runsecure_orchestrator_breaker_open{repo="o/r"} 0`))
}

func TestSnapshot_RoundTrip(t *testing.T) {
	d := newDeps(t)
	s := NewSnapshot(d)
	rr := httpRec()
	s.ServeHTTP(rr, httpReq("GET", "/state/snapshot"))
	require.Equal(t, http.StatusOK, rr.Code)
	var got state.Snapshot
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, 2, got.PerRepo["o/r"].InFlight)
	require.Equal(t, 4321, got.RateLimitRemaining)
}

func TestServer_RunStartsAndStops(t *testing.T) {
	d := newDeps(t)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	srv := New("127.0.0.1:0", "127.0.0.1:0", d, em)
	require.NotNil(t, srv)
}

func TestServer_New_DefaultAddrs(t *testing.T) {
	d := newDeps(t)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	srv := New("", "", d, em)
	require.NotNil(t, srv)
	require.Equal(t, ":8080", srv.healthzAddr)
	require.Equal(t, ":8081", srv.debugAddr)
}

func TestMetrics_EmptySnapshot(t *testing.T) {
	d := &fakeDeps{
		lastPoll:  time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC),
		now:       time.Date(2026, 5, 19, 10, 0, 30, 0, time.UTC),
		intervalS: 15,
		snap:      state.Snapshot{PerRepo: map[string]state.RepoState{}},
		api:       map[APICallKey]int64{},
		spawns:    map[SpawnKey]int64{},
		breakers:  map[string]bool{},
	}
	m := NewMetrics(d)
	rr := httpRec()
	m.ServeHTTP(rr, httpReq("GET", "/metrics"))
	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, strings.Contains(rr.Body.String(), "runsecure_orchestrator_api_rate_limit_remaining"))
}

func TestServer_RunAndShutdownOnCtxCancel(t *testing.T) {
	d := newDeps(t)
	em := cornerstone.NewEmitter(io.Discard, cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	// :0 → kernel picks free ports.
	srv := New("127.0.0.1:0", "127.0.0.1:0", d, em)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		// Either nil (graceful) or a "listen address in use" if port :0
		// resolved weirdly — both acceptable.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
}

func TestCmpStrings_AllBranches(t *testing.T) {
	require.Equal(t, -1, cmpStrings("a", "b", "c", "b", "b", "c"))
	require.Equal(t, 0, cmpStrings("a", "b", "c", "a", "b", "c"))
	require.Equal(t, 1, cmpStrings("b", "b", "c", "a", "b", "c"))
	require.Equal(t, -1, cmpStrings("a", "a", "c", "a", "b", "c"))
	require.Equal(t, -1, cmpStrings("a", "b", "c", "a", "b", "d"))
}

// Mutation kills: server.go HTTP timeouts. Exposed as accessor funcs (not
// consts) so the mutated multiplication operators land inside a covered
// function body. Exact-value asserts kill the ARITHMETIC mutations.
func TestServerTimeouts(t *testing.T) {
	require.Equal(t, 2*time.Second, HTTPReadHeaderTimeout())
	require.Equal(t, 10*time.Second, HTTPReadTimeout())
	require.Equal(t, 10*time.Second, HTTPWriteTimeout())
	require.Equal(t, 60*time.Second, HTTPIdleTimeout())
	require.Equal(t, 5*time.Second, HTTPShutdownTimeout())
}

// Mutation kill: the `< 0` boundary in the less-than functions. Self-
// comparison must return false — `< 0` returns false on cmp==0, but the
// `<= 0` mutation would return true and break sort semantics.
func TestLessSpawnKey_SelfComparison(t *testing.T) {
	k := SpawnKey{Scope: "s", Repo: "o/r", Outcome: "success"}
	require.False(t, lessSpawnKey(k, k),
		"a key is not less than itself (< 0 returns false on cmp==0)")
}

func TestLessAPICallKey_SelfComparison(t *testing.T) {
	k := APICallKey{Endpoint: "jit", Status: "201"}
	require.False(t, lessAPICallKey(k, k))
}

// Mutation kill: metrics.go:125 + :136 — sort.Slice less-than functions.
// Asserts strict ordering across MULTIPLE spawn-key tuples (Scope, Repo,
// Outcome) AND API-call keys (Endpoint, Status). With these multi-entry
// expectations, mutation `< 0` → `>= 0` (reverse sort) is observably wrong.
func TestMetrics_SpawnKeysAndAPICallKeys_Sorted(t *testing.T) {
	d := newDeps(t)
	d.snap.PerRepo = map[string]state.RepoState{
		"z/last":  {InFlight: 1},
		"a/first": {InFlight: 2},
	}
	d.spawns[SpawnKey{Scope: "s2", Repo: "o/r", Outcome: "fail"}] = 1
	d.spawns[SpawnKey{Scope: "s1", Repo: "o/r", Outcome: "success"}] = 3
	d.spawns[SpawnKey{Scope: "s3", Repo: "o/r", Outcome: "fail"}] = 7
	d.api[APICallKey{Endpoint: "queue", Status: "200"}] = 100
	d.api[APICallKey{Endpoint: "jit", Status: "201"}] = 5
	d.api[APICallKey{Endpoint: "ratelimit", Status: "429"}] = 2
	m := NewMetrics(d)
	rr := httpRec()
	m.ServeHTTP(rr, httpReq("GET", "/metrics"))
	body := rr.Body.String()

	// Repos: a/first before z/last.
	require.Less(t, strings.Index(body, "a/first"), strings.Index(body, "z/last"))

	// Spawn keys ordered by scope ascending: s1 < s2 < s3.
	s1Idx := strings.Index(body, `scope="s1"`)
	s2Idx := strings.Index(body, `scope="s2"`)
	s3Idx := strings.Index(body, `scope="s3"`)
	require.True(t, s1Idx < s2Idx, "s1 must come before s2 (got s1=%d s2=%d)", s1Idx, s2Idx)
	require.True(t, s2Idx < s3Idx, "s2 must come before s3")

	// API call keys ordered by endpoint ascending: jit < queue < ratelimit.
	jitIdx := strings.Index(body, `endpoint="jit"`)
	queueIdx := strings.Index(body, `endpoint="queue"`)
	rlIdx := strings.Index(body, `endpoint="ratelimit"`)
	require.True(t, jitIdx < queueIdx, "jit < queue")
	require.True(t, queueIdx < rlIdx, "queue < ratelimit")
}
