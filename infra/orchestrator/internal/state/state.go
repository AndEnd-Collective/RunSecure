// Package state holds in-memory orchestrator state — per-repo in-flight
// counters with semaphore-style cap enforcement, plus per-scope rate-limit
// awareness. Persistent state is not needed: cold-start rebuilds from
// docker container labels (see coldstart.go) and drift reconciliation
// (see drift.go) keeps the in-memory view honest against docker's truth.
package state

import (
	"sync"
	"time"
)

type State struct {
	mu      sync.RWMutex
	perRepo map[string]*RepoState
	// rateLimitContext is per-scope but only one scope per orchestrator process,
	// so we store it inline.
	rlRemaining int
	rlLimit     int
	rlReset     time.Time
}

type RepoState struct {
	InFlight    int
	BreakerOpen bool // surfaced from breaker pkg; see breaker.go
	LastPollAt  time.Time
	LastETag    string // for runner.yml ETag caching (k8s — unused in Plan A)
}

func New() *State {
	return &State{perRepo: map[string]*RepoState{}}
}

func (s *State) ensure(repo string) *RepoState {
	if r, ok := s.perRepo[repo]; ok {
		return r
	}
	r := &RepoState{}
	s.perRepo[repo] = r
	return r
}

func (s *State) InFlight(repo string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.perRepo[repo]; ok {
		return r.InFlight
	}
	return 0
}

func (s *State) GlobalInFlight() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, r := range s.perRepo {
		total += r.InFlight
	}
	return total
}

// AcquireSemaphores atomically increments the per-repo counter iff both
// caps would still be respected. Returns true on success.
func (s *State) AcquireSemaphores(repo string, repoCap, globalCap int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ensure(repo)
	if r.InFlight >= repoCap {
		return false
	}
	total := 0
	for _, x := range s.perRepo {
		total += x.InFlight
	}
	if total >= globalCap {
		return false
	}
	r.InFlight++
	return true
}

// ReleaseSemaphores decrements the per-repo counter (floor 0).
func (s *State) ReleaseSemaphores(repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ensure(repo)
	if r.InFlight > 0 {
		r.InFlight--
	}
}

// IncrementInFlight is used by cold-start reconciliation only — bypasses
// the cap check because docker is the source of truth for already-running
// containers.
func (s *State) IncrementInFlight(repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure(repo).InFlight++
}

func (s *State) DecrementInFlight(repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ensure(repo)
	if r.InFlight > 0 {
		r.InFlight--
	}
}

func (s *State) SetRateLimit(remaining, limit int, reset time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rlRemaining = remaining
	s.rlLimit = limit
	s.rlReset = reset
}

func (s *State) RateLimit() (remaining, limit int, reset time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rlRemaining, s.rlLimit, s.rlReset
}

// Snapshot returns a copy of state for /state/snapshot debugging.
type Snapshot struct {
	PerRepo            map[string]RepoState `json:"per_repo"`
	GlobalInFlight     int                  `json:"global_in_flight"`
	RateLimitRemaining int                  `json:"rate_limit_remaining"`
	RateLimitLimit     int                  `json:"rate_limit_limit"`
	RateLimitReset     time.Time            `json:"rate_limit_reset"`
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		PerRepo:            make(map[string]RepoState, len(s.perRepo)),
		RateLimitRemaining: s.rlRemaining,
		RateLimitLimit:     s.rlLimit,
		RateLimitReset:     s.rlReset,
	}
	total := 0
	for k, r := range s.perRepo {
		snap.PerRepo[k] = *r
		total += r.InFlight
	}
	snap.GlobalInFlight = total
	return snap
}

// LastETag returns the cached ETag for the given repo's runner.yml.
// It is used by the kube backend to perform conditional GitHub API requests.
func (s *State) LastETag(repo string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.perRepo[repo]; ok {
		return r.LastETag
	}
	return ""
}

// SetLastETag updates the cached ETag for the given repo's runner.yml.
func (s *State) SetLastETag(repo, etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure(repo).LastETag = etag
}

// AllRepos returns the names of repos that have non-zero state recorded.
// Used by drift reconciliation.
func (s *State) AllRepos() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.perRepo))
	for k := range s.perRepo {
		out = append(out, k)
	}
	return out
}
