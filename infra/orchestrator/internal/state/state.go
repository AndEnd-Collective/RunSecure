// Package state holds the orchestrator's in-memory scheduling and lifecycle
// state. Capacity reservations are created before intents are enqueued so
// consecutive poll ticks cannot over-spawn while JIT runners are registering.
package state

import (
	"sync"
	"time"
)

// SpawnPhase is the observable lifecycle phase of an active reservation.
type SpawnPhase string

const (
	PhasePending  SpawnPhase = "pending"
	PhaseOnline   SpawnPhase = "online"
	PhaseAssigned SpawnPhase = "assigned"
)

// SpawnState correlates an orchestrator spawn with its GitHub runner.
type SpawnState struct {
	SpawnID    string     `json:"spawn_id"`
	Repo       string     `json:"repo"`
	Phase      SpawnPhase `json:"phase"`
	RunnerID   int64      `json:"runner_id,omitempty"`
	RunnerName string     `json:"runner_name,omitempty"`
	ReservedAt time.Time  `json:"reserved_at"`
	OnlineAt   time.Time  `json:"online_at,omitempty"`
	AssignedAt time.Time  `json:"assigned_at,omitempty"`
}

type State struct {
	mu           sync.RWMutex
	perRepo      map[string]*RepoState
	reservations map[string]*SpawnState
	rlRemaining  int
	rlLimit      int
	rlReset      time.Time

	configuredCapacity int
	workerCapacity     int
	version            string
	buildSHA           string
	configLoaded       bool
	draining           bool
	assignmentsTotal   int64
	completedTotal     int64
	unassignedTotal    int64
	deregisteredTotal  int64
}

type RepoState struct {
	InFlight        int       `json:"in_flight"`
	QueuedJobs      int       `json:"queued_jobs"`
	Pending         int       `json:"pending"`
	Online          int       `json:"online"`
	Assigned        int       `json:"assigned"`
	BreakerOpen     bool      `json:"breaker_open"`
	LastPollAt      time.Time `json:"last_poll_at,omitempty"`
	LastPollSuccess time.Time `json:"last_poll_success,omitempty"`
	LastPollError   string    `json:"last_poll_error,omitempty"`
	LastErrorDetail string    `json:"last_error_detail,omitempty"`
	LastETag        string    `json:"last_etag,omitempty"`
}

func New() *State {
	return &State{perRepo: map[string]*RepoState{}, reservations: map[string]*SpawnState{}}
}

// Configure records immutable runtime metadata and ensures every configured
// repository appears in readiness, snapshot, and metrics output before its
// first successful poll.
func (s *State) Configure(repos []string, configuredCapacity, workerCapacity int, version, buildSHA string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, repo := range repos {
		s.ensure(repo)
	}
	s.configuredCapacity = configuredCapacity
	s.workerCapacity = workerCapacity
	s.version = version
	s.buildSHA = buildSHA
	s.configLoaded = true
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
	return s.globalInFlightLocked()
}

func (s *State) globalInFlightLocked() int {
	total := 0
	for _, r := range s.perRepo {
		total += r.InFlight
	}
	return total
}

// TryReserve atomically consumes repo and global capacity for spawnID.
func (s *State) TryReserve(spawnID, repo string, repoCap, globalCap int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.reservations[spawnID]; ok {
		return existing.Repo == repo
	}
	r := s.ensure(repo)
	if r.InFlight >= repoCap || s.globalInFlightLocked() >= globalCap {
		return false
	}
	r.InFlight++
	r.Pending++
	s.reservations[spawnID] = &SpawnState{
		SpawnID: spawnID, Repo: repo, Phase: PhasePending, ReservedAt: now,
	}
	return true
}

// HasReservation reports whether spawnID has consumed capacity.
func (s *State) HasReservation(spawnID, repo string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reservations[spawnID]
	return ok && r.Repo == repo
}

// RecordJIT attaches the GitHub runner identity to a reservation.
func (s *State) RecordJIT(spawnID string, runnerID int64, runnerName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spawn, ok := s.reservations[spawnID]; ok {
		spawn.RunnerID = runnerID
		spawn.RunnerName = runnerName
	}
}

func (s *State) MarkOnline(spawnID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok || spawn.Phase != PhasePending {
		return false
	}
	r := s.ensure(spawn.Repo)
	if r.Pending > 0 {
		r.Pending--
	}
	r.Online++
	spawn.Phase = PhaseOnline
	spawn.OnlineAt = now
	return true
}

func (s *State) MarkAssigned(spawnID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok || spawn.Phase == PhaseAssigned {
		return false
	}
	r := s.ensure(spawn.Repo)
	if spawn.Phase == PhasePending && r.Pending > 0 {
		r.Pending--
	}
	if spawn.Phase == PhaseOnline && r.Online > 0 {
		r.Online--
	}
	r.Assigned++
	spawn.Phase = PhaseAssigned
	spawn.AssignedAt = now
	s.assignmentsTotal++
	return true
}

// ReleaseReservation removes capacity and its phase component exactly once.
func (s *State) ReleaseReservation(spawnID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok {
		return
	}
	r := s.ensure(spawn.Repo)
	if r.InFlight > 0 {
		r.InFlight--
	}
	switch spawn.Phase {
	case PhasePending:
		if r.Pending > 0 {
			r.Pending--
		}
	case PhaseOnline:
		if r.Online > 0 {
			r.Online--
		}
	case PhaseAssigned:
		if r.Assigned > 0 {
			r.Assigned--
		}
	}
	delete(s.reservations, spawnID)
}

func (s *State) RecordCompleted() {
	s.mu.Lock()
	s.completedTotal++
	s.mu.Unlock()
}

func (s *State) RecordUnassignedExit() {
	s.mu.Lock()
	s.unassignedTotal++
	s.mu.Unlock()
}

func (s *State) RecordDeregistered() {
	s.mu.Lock()
	s.deregisteredTotal++
	s.mu.Unlock()
}

func (s *State) RecordPollAttempt(repo string, at time.Time) {
	s.mu.Lock()
	s.ensure(repo).LastPollAt = at
	s.mu.Unlock()
}

func (s *State) RecordPollSuccess(repo string, queued int, at time.Time) {
	s.mu.Lock()
	r := s.ensure(repo)
	r.QueuedJobs = queued
	r.LastPollSuccess = at
	r.LastPollError = ""
	r.LastErrorDetail = ""
	s.mu.Unlock()
}

func (s *State) RecordPollFailure(repo, class, detail string) {
	s.mu.Lock()
	r := s.ensure(repo)
	r.LastPollError = class
	r.LastErrorDetail = detail
	s.mu.Unlock()
}

func (s *State) SetBreakerOpen(repo string, open bool) {
	s.mu.Lock()
	s.ensure(repo).BreakerOpen = open
	s.mu.Unlock()
}

func (s *State) SetDraining(draining bool) {
	s.mu.Lock()
	s.draining = draining
	s.mu.Unlock()
}

// AcquireSemaphores is retained for cold-start and compatibility callers. New
// scheduler paths use TryReserve so pending work is visible before execution.
func (s *State) AcquireSemaphores(repo string, repoCap, globalCap int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ensure(repo)
	if r.InFlight >= repoCap || s.globalInFlightLocked() >= globalCap {
		return false
	}
	r.InFlight++
	return true
}

func (s *State) ReleaseSemaphores(repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ensure(repo)
	if r.InFlight > 0 {
		r.InFlight--
	}
}

func (s *State) IncrementInFlight(repo string) {
	s.mu.Lock()
	s.ensure(repo).InFlight++
	s.mu.Unlock()
}

func (s *State) DecrementInFlight(repo string) {
	s.mu.Lock()
	r := s.ensure(repo)
	if r.InFlight > 0 {
		r.InFlight--
	}
	s.mu.Unlock()
}

func (s *State) SetRateLimit(remaining, limit int, reset time.Time) {
	s.mu.Lock()
	s.rlRemaining = remaining
	s.rlLimit = limit
	s.rlReset = reset
	s.mu.Unlock()
}

func (s *State) RateLimit() (remaining, limit int, reset time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rlRemaining, s.rlLimit, s.rlReset
}

// Snapshot is the complete operator-visible runtime state.
type Snapshot struct {
	PerRepo              map[string]RepoState  `json:"per_repo"`
	Reservations         map[string]SpawnState `json:"reservations"`
	GlobalInFlight       int                   `json:"global_in_flight"`
	RateLimitRemaining   int                   `json:"rate_limit_remaining"`
	RateLimitLimit       int                   `json:"rate_limit_limit"`
	RateLimitReset       time.Time             `json:"rate_limit_reset"`
	ConfiguredCapacity   int                   `json:"configured_capacity"`
	WorkerCapacity       int                   `json:"worker_capacity"`
	Version              string                `json:"version"`
	BuildSHA             string                `json:"build_sha"`
	ConfigLoaded         bool                  `json:"config_loaded"`
	Draining             bool                  `json:"draining"`
	AssignmentsTotal     int64                 `json:"assignments_total"`
	CompletedTotal       int64                 `json:"completed_total"`
	UnassignedExitsTotal int64                 `json:"unassigned_exits_total"`
	DeregistrationsTotal int64                 `json:"deregistrations_total"`
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		PerRepo:              make(map[string]RepoState, len(s.perRepo)),
		Reservations:         make(map[string]SpawnState, len(s.reservations)),
		RateLimitRemaining:   s.rlRemaining,
		RateLimitLimit:       s.rlLimit,
		RateLimitReset:       s.rlReset,
		ConfiguredCapacity:   s.configuredCapacity,
		WorkerCapacity:       s.workerCapacity,
		Version:              s.version,
		BuildSHA:             s.buildSHA,
		ConfigLoaded:         s.configLoaded,
		Draining:             s.draining,
		AssignmentsTotal:     s.assignmentsTotal,
		CompletedTotal:       s.completedTotal,
		UnassignedExitsTotal: s.unassignedTotal,
		DeregistrationsTotal: s.deregisteredTotal,
	}
	for repo, r := range s.perRepo {
		snap.PerRepo[repo] = *r
		snap.GlobalInFlight += r.InFlight
	}
	for spawnID, reservation := range s.reservations {
		snap.Reservations[spawnID] = *reservation
	}
	return snap
}

func (s *State) LastETag(repo string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.perRepo[repo]; ok {
		return r.LastETag
	}
	return ""
}

func (s *State) SetLastETag(repo, etag string) {
	s.mu.Lock()
	s.ensure(repo).LastETag = etag
	s.mu.Unlock()
}

func (s *State) AllRepos() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.perRepo))
	for repo := range s.perRepo {
		out = append(out, repo)
	}
	return out
}
