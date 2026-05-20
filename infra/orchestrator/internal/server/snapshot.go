package server

import (
	"encoding/json"
	"net/http"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
)

// SnapshotDeps exposes state snapshot for the debug endpoint.
type SnapshotDeps interface {
	StateSnapshot() state.Snapshot
}

// Snapshot serves GET /state/snapshot as JSON.
type Snapshot struct {
	deps SnapshotDeps
}

func NewSnapshot(deps SnapshotDeps) *Snapshot {
	return &Snapshot{deps: deps}
}

func (s *Snapshot) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.deps.StateSnapshot())
}
