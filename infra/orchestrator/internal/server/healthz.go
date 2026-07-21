// Package server exposes the orchestrator's HTTP introspection endpoints
// on localhost (never publicly): /healthz, /metrics, /state/snapshot.
//
// Two listeners:
//   - :8080 for /healthz (used by docker HEALTHCHECK and supervisors)
//   - :8081 for /metrics + /state/snapshot (operator-visible only)
package server

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
)

// HealthDeps exposes a poll-staleness signal to the /healthz handler.
type HealthDeps interface {
	LastPollAt() time.Time
	PollStarted() bool
	PollIntervalSeconds() int
	Now() time.Time
}

// Healthz handles GET /healthz.
//
// Before the poll loop starts, 200 reports that the process is live during
// cold-start reconciliation. Afterwards, 200 requires
// now-last_poll_tick < 3*poll_interval_seconds; stale polling returns 500.
// Emits a Debug-severity Cornerstone event on every probe (off by default
// at runtime log filtering).
type Healthz struct {
	deps HealthDeps
	em   *cornerstone.Emitter
	hits atomic.Int64
}

func NewHealthz(deps HealthDeps, em *cornerstone.Emitter) *Healthz {
	return &Healthz{deps: deps, em: em}
}

func (h *Healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.hits.Add(1)
	_ = h.em.EmitHealthProbe()
	// The management listener is deliberately bound before cold-start backend
	// reconciliation. Until the poll loop has actually started there is no poll
	// cadence to declare stale; process liveness remains green while readiness
	// continues to fail closed on backend and demand-refresh state.
	if !h.deps.PollStarted() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"starting"}`))
		return
	}
	staleness := h.deps.Now().Sub(h.deps.LastPollAt())
	limit := time.Duration(3*h.deps.PollIntervalSeconds()) * time.Second
	if staleness >= limit {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"stale"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Hits exposes the probe count for tests.
func (h *Healthz) Hits() int64 { return h.hits.Load() }
