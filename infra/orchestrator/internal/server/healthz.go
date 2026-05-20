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
	PollIntervalSeconds() int
	Now() time.Time
}

// Healthz handles GET /healthz.
//
// 200 if now - last_poll_tick < 3 * poll_interval_seconds, else 500.
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
