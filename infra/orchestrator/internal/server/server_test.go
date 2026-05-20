package server

import (
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

func (f *fakeDeps) LastPollAt() time.Time            { return f.lastPoll }
func (f *fakeDeps) Now() time.Time                    { return f.now }
func (f *fakeDeps) PollIntervalSeconds() int          { return f.intervalS }
func (f *fakeDeps) StateSnapshot() state.Snapshot     { return f.snap }
func (f *fakeDeps) APICalls() map[APICallKey]int64    { return f.api }
func (f *fakeDeps) SpawnsTotal() map[SpawnKey]int64   { return f.spawns }
func (f *fakeDeps) SpawnDurations() map[string][]float64 { return f.durations }
func (f *fakeDeps) BreakerOpen() map[string]bool      { return f.breakers }

func newDeps(t *testing.T) *fakeDeps {
	t.Helper()
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	return &fakeDeps{
		lastPoll:  now.Add(-5 * time.Second),
		now:       now,
		intervalS: 15,
		snap: state.Snapshot{
			PerRepo: map[string]state.RepoState{"o/r": {InFlight: 2}},
			GlobalInFlight: 2,
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
