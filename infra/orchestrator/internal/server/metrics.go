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
	// queued_jobs
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_queued_jobs Eligible queued workflow jobs observed at the last successful poll.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_queued_jobs gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_queued_jobs{repo=%q} %d\n", repo, snap.PerRepo[repo].QueuedJobs)
	}
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_repo_last_poll_attempt_timestamp_seconds Unix epoch of the last GitHub demand-refresh attempt.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_repo_last_poll_attempt_timestamp_seconds gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_repo_last_poll_attempt_timestamp_seconds{repo=%q} %d\n", repo, epochOrZero(snap.PerRepo[repo].LastPollAt))
	}
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_repo_last_poll_success_timestamp_seconds Unix epoch of the last successful GitHub demand refresh.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_repo_last_poll_success_timestamp_seconds gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_repo_last_poll_success_timestamp_seconds{repo=%q} %d\n", repo, epochOrZero(snap.PerRepo[repo].LastPollSuccess))
	}
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_poll_error_info Last classified GitHub demand-refresh error.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_poll_error_info gauge")
	for _, repo := range sortedKeys(snap.PerRepo) {
		if class := snap.PerRepo[repo].LastPollError; class != "" {
			fmt.Fprintf(w, "runsecure_orchestrator_poll_error_info{repo=%q,class=%q} 1\n", repo, class)
		}
	}
	renderPhaseGauge(w, "pending_runners", "Reserved runners not yet observed online.", snap, func(r state.RepoState) int { return r.Pending })
	renderPhaseGauge(w, "online_runners", "Online runners waiting for assignment.", snap, func(r state.RepoState) int { return r.Online })
	renderPhaseGauge(w, "assigned_runners", "Runners observed assigned to a job.", snap, func(r state.RepoState) int { return r.Assigned })
	renderPhaseGauge(w, "teardown_blocked_reservations", "Reservations retained after backend teardown failure.", snap, func(r state.RepoState) int { return r.TeardownBlocked })
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
	rateLimited := 0
	if snap.RateLimited {
		rateLimited = 1
	}
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_rate_limited Whether scheduling is paused by a GitHub rate limit.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_rate_limited gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_rate_limited %d\n", rateLimited)
	// last_poll_timestamp_seconds
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_last_poll_timestamp_seconds Unix epoch of the last poll-loop tick.")
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
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_configured_capacity Configured global runner capacity.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_configured_capacity gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_configured_capacity %d\n", snap.ConfiguredCapacity)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_worker_capacity Spawn worker pool size.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_worker_capacity gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_worker_capacity %d\n", snap.WorkerCapacity)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_assignments_total Runners observed assigned to jobs.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_assignments_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_assignments_total %d\n", snap.AssignmentsTotal)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_completed_runners_total Assigned runners whose process completed.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_completed_runners_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_completed_runners_total %d\n", snap.CompletedTotal)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_unassigned_exits_total Runners that exited without observed assignment.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_unassigned_exits_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_unassigned_exits_total %d\n", snap.UnassignedExitsTotal)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_deregistrations_total JIT runner registrations confirmed removed.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_deregistrations_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_deregistrations_total %d\n", snap.DeregistrationsTotal)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_teardown_failures_total Backend teardown failures that blocked scheduling.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_teardown_failures_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_teardown_failures_total %d\n", snap.TeardownFailuresTotal)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_teardown_reconciled_total Blocked teardowns resolved by exact-handle retry.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_teardown_reconciled_total counter")
	fmt.Fprintf(w, "runsecure_orchestrator_teardown_reconciled_total %d\n", snap.TeardownReconciledTotal)
	draining := 0
	if snap.Draining {
		draining = 1
	}
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_draining Whether the orchestrator is draining.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_draining gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_draining %d\n", draining)
	fmt.Fprintln(w, "# HELP runsecure_orchestrator_build_info Build provenance for this orchestrator.")
	fmt.Fprintln(w, "# TYPE runsecure_orchestrator_build_info gauge")
	fmt.Fprintf(w, "runsecure_orchestrator_build_info{version=%q,build_sha=%q} 1\n", snap.Version, snap.BuildSHA)
	return nil
}

func epochOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func renderPhaseGauge(w io.Writer, name, help string, snap state.Snapshot, value func(state.RepoState) int) {
	fmt.Fprintf(w, "# HELP runsecure_orchestrator_%s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE runsecure_orchestrator_%s gauge\n", name)
	for _, repo := range sortedKeys(snap.PerRepo) {
		fmt.Fprintf(w, "runsecure_orchestrator_%s{repo=%q} %d\n", name, repo, value(snap.PerRepo[repo]))
	}
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

// lessSpawnKey is the comparator for sortedSpawnKeys. Extracted so tests
// can probe the `< 0` boundary directly with equal inputs (mutation `<= 0`
// would return true for self-comparison while `< 0` correctly returns false).
func lessSpawnKey(a, b SpawnKey) bool {
	return cmpStrings(a.Scope, a.Repo, a.Outcome, b.Scope, b.Repo, b.Outcome) < 0
}

func sortedSpawnKeys(m map[SpawnKey]int64) []SpawnKey {
	out := make([]SpawnKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return lessSpawnKey(out[i], out[j]) })
	return out
}

func lessAPICallKey(a, b APICallKey) bool {
	return strings.Compare(a.Endpoint+"|"+a.Status, b.Endpoint+"|"+b.Status) < 0
}

func sortedAPICallKeys(m map[APICallKey]int64) []APICallKey {
	out := make([]APICallKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return lessAPICallKey(out[i], out[j]) })
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
