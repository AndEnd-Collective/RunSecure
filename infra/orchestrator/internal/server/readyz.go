package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
)

// ReadyDeps exposes the live dependency and poll-success state needed for
// readiness. Liveness intentionally uses a smaller interface in healthz.go.
type ReadyDeps interface {
	StateSnapshot() state.Snapshot
	PollIntervalSeconds() int
	Now() time.Time
	BackendReady(context.Context) error
}

type readinessResponse struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

type Readyz struct{ deps ReadyDeps }

func NewReadyz(deps ReadyDeps) *Readyz { return &Readyz{deps: deps} }

func (h *Readyz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	reasons := readinessReasons(h.deps.StateSnapshot(), h.deps.Now(), h.deps.PollIntervalSeconds())
	if err := h.deps.BackendReady(ctx); err != nil {
		reasons = append(reasons, "backend_unreachable")
	}
	sort.Strings(reasons)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	body := readinessResponse{Status: "ready"}
	if len(reasons) > 0 {
		status = http.StatusServiceUnavailable
		body = readinessResponse{Status: "not_ready", Reasons: reasons}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func readinessReasons(snap state.Snapshot, now time.Time, pollIntervalSeconds int) []string {
	reasons := []string{}
	if !snap.ConfigLoaded {
		reasons = append(reasons, "config_not_loaded")
	}
	if snap.Draining {
		reasons = append(reasons, "draining")
	}
	limit := time.Duration(3*pollIntervalSeconds) * time.Second
	for repo, repoState := range snap.PerRepo {
		switch {
		case repoState.LastPollSuccess.IsZero():
			reasons = append(reasons, "poll_never_succeeded:"+repo)
		case now.Sub(repoState.LastPollSuccess) >= limit:
			reasons = append(reasons, "poll_stale:"+repo)
		}
		if repoState.LastPollError != "" {
			reasons = append(reasons, "poll_error:"+repo+":"+repoState.LastPollError)
		}
		if repoState.BreakerOpen {
			reasons = append(reasons, "breaker_open:"+repo)
		}
	}
	return reasons
}
