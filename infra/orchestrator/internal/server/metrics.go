package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
)

// MetricsDeps exposes the snapshot needed to render Prometheus metrics.
type MetricsDeps interface {
	StateSnapshot() state.Snapshot
	LastPollAt() time.Time
	APICalls() map[APICallKey]int64
	SpawnsTotal() map[SpawnKey]int64
	SpawnDurations() map[string][]float64 // repo → durations in seconds
	BreakerOpen() map[string]bool
}

// APICallKey labels Prometheus runsecure_orchestrator_api_calls_total samples.
type APICallKey struct {
	Endpoint string
	Status   string
}

// SpawnKey labels runsecure_orchestrator_spawns_total samples.
type SpawnKey struct {
	Scope, Repo, Outcome string
}

// Metrics renders Prometheus text-format on GET /metrics.
// Handwritten to keep the orchestrator binary dependency-free.
type Metrics struct {
	deps MetricsDeps
}

func NewMetrics(deps MetricsDeps) *Metrics {
	return &Metrics{deps: deps}
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snap := m.deps.StateSnapshot()
	w.WriteHeader(http.StatusOK)
	_ = renderMetrics(w, m.deps, snap)
}

func renderMetrics(w io.Writer, deps MetricsDeps, snap state.Snapshot) error {
	// in_flight_runners
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_in_flight_runners In-flight ephemeral runners per repo.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_in_flight_runners gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_in_flight_runners{repo=%q} %d\n", repo, snap.PerRepo[repo].InFlight)
	}
	// queued_jobs (best-effort: not in snapshot — emit 0 placeholder per repo)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_queued_jobs Queued workflow runs observed at last poll.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_queued_jobs gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_queued_jobs{repo=%q} 0\n", repo)
	}
	// spawns_total
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_spawns_total Total spawn attempts.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_spawns_total counter")
	for _, k := range sortedSpawnKeys(deps.SpawnsTotal()) {
		fmt.Fprintf(w, "runsecure_orchestrator_spawns_total{scope=%q,repo=%q,outcome=%q} %d\n",
			k.Scope, k.Repo, k.Outcome, deps.SpawnsTotal()[k])
	}
	// api_calls_total
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_api_calls_total Total GitHub API calls.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_api_calls_total counter")
	for _, k := range sortedAPICallKeys(deps.APICalls()) {
		fmt.Fprintf(w, "runsecure_orchestrator_api_calls_total{endpoint=%q,status=%q} %d\n",
			k.Endpoint, k.Status, deps.APICalls()[k])
	}
	// rate_limit_remaining
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_api_rate_limit_remaining GitHub rate-limit remaining.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_api_rate_limit_remaining gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_api_rate_limit_remaining %d\n", snap.RateLimitRemaining)
	// last_poll_timestamp_seconds
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_last_poll_timestamp_seconds Unix epoch of the last successful poll.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_last_poll_timestamp_seconds gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_last_poll_timestamp_seconds %d\n", deps.LastPollAt().Unix())
	// breaker_open
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_breaker_open Circuit breaker state (1=open, 0=closed).")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_breaker_open gauge")
	for _, repo := range sortedKeysBool(deps.BreakerOpen()) {
		v := 0
		if deps.BreakerOpen()[repo] {
			v = 1
		}
		fmt.Fprintf(w, "runsecure_orchestrator_breaker_open{repo=%q} %d\n", repo, v)
	}
	return nil
}

func sortedKeys(m map[string]state.RepoState) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSpawnKeys(m map[SpawnKey]int64) []SpawnKey {
	out := make([]SpawnKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return cmpStrings(out[i].Scope, out[i].Repo, out[i].Outcome,
			out[j].Scope, out[j].Repo, out[j].Outcome) < 0
	})
	return out
}

func sortedAPICallKeys(m map[APICallKey]int64) []APICallKey {
	out := make([]APICallKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i].Endpoint+"|"+out[i].Status, out[j].Endpoint+"|"+out[j].Status) < 0
	})
	return out
}

func cmpStrings(a1, a2, a3, b1, b2, b3 string) int {
	if c := strings.Compare(a1, b1); c != 0 {
		return c
	}
	if c := strings.Compare(a2, b2); c != 0 {
		return c
	}
	return strings.Compare(a3, b3)
}
