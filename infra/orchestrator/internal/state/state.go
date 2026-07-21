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
	// PhaseTeardownBlocked is capacity debt: backend teardown returned an
	// error, so the reservation must remain charged until an exact retry of
	// that teardown succeeds.
	PhaseTeardownBlocked SpawnPhase = "teardown_blocked"
)

// SpawnState correlates an orchestrator spawn with its GitHub runner.
type SpawnState struct {
	SpawnID           string     `json:"spawn_id"`
	Repo              string     `json:"repo"`
	Phase             SpawnPhase `json:"phase"`
	RunnerID          int64      `json:"runner_id,omitempty"`
	RunnerName        string     `json:"runner_name,omitempty"`
	AssignedJobID     int64      `json:"assigned_job_id,omitempty"`
	ReservedAt        time.Time  `json:"reserved_at"`
	OnlineAt          time.Time  `json:"online_at,omitempty"`
	AssignedAt        time.Time  `json:"assigned_at,omitempty"`
	TeardownBlockedAt time.Time  `json:"teardown_blocked_at,omitempty"`
	TeardownFailure   string     `json:"teardown_failure,omitempty"`
}

type State struct {
	mu           sync.RWMutex
	perRepo      map[string]*RepoState
	reservations map[string]*SpawnState
	consumedJobs map[string]map[int64]struct{}
	rlRemaining  int
	rlLimit      int
	rlReset      time.Time
	rateLimited  bool

	configuredCapacity int
	workerCapacity     int
	version            string
	buildSHA           string
	configLoaded       bool
	draining           bool
	teardownBlocked    bool
	assignmentsTotal   int64
	completedTotal     int64
	unassignedTotal    int64
	deregisteredTotal  int64
	teardownFailures   int64
	teardownReconciled int64
}

type RepoState struct {
	InFlight             int                       `json:"in_flight"`
	QueuedJobs           int                       `json:"queued_jobs"`
	Pending              int                       `json:"pending"`
	Online               int                       `json:"online"`
	Assigned             int                       `json:"assigned"`
	TeardownBlocked      int                       `json:"teardown_blocked"`
	BreakerOpen          bool                      `json:"breaker_open"`
	LastPollAt           time.Time                 `json:"last_poll_at,omitempty"`
	LastPollSuccess      time.Time                 `json:"last_poll_success,omitempty"`
	LastPollError        string                    `json:"last_poll_error,omitempty"`
	LastErrorDetail      string                    `json:"last_error_detail,omitempty"`
	RunnerOperationError map[string]OperationError `json:"runner_operation_errors,omitempty"`
	LastETag             string                    `json:"last_etag,omitempty"`
}

// OperationError is an unresolved runner-management capability failure.
// Demand polling is deliberately tracked separately: a successful read-only
// queue refresh cannot prove that JIT creation, runner observation, or runner
// deletion is authorized.
type OperationError struct {
	Class  string `json:"class"`
	Detail string `json:"detail"`
}

func New() *State {
	return &State{
		perRepo:      map[string]*RepoState{},
		reservations: map[string]*SpawnState{},
		consumedJobs: map[string]map[int64]struct{}{},
	}
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
		if r.RunnerOperationError == nil {
			r.RunnerOperationError = map[string]OperationError{}
		}
		return r
	}
	r := &RepoState{RunnerOperationError: map[string]OperationError{}}
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

// ReconcileDemand reports capacity already promised to the exact queued job
// IDs in a successful GitHub refresh. Pending and online runners are generic
// capacity and cover any queued job. Active assignments and consumed-job
// tombstones cover a job only while GitHub still reports that same ID as
// queued. Tombstones survive runner teardown and are cleared when a successful
// refresh omits that ID because Actions job status cannot move back to queued.
//
// MarkAssigned and ReconcileDemand use the same lock. Therefore an online
// runner can never disappear from coverage between the demand snapshot and
// admission: it is observed either as generic online capacity or as the exact
// consumed job ID, without a timing-based guess.
func (s *State) ReconcileDemand(repo string, queuedJobIDs []int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.perRepo[repo]
	if !ok {
		return 0
	}
	coverage := r.Pending + r.Online
	queued := make(map[int64]struct{}, len(queuedJobIDs))
	for _, jobID := range queuedJobIDs {
		if jobID > 0 {
			queued[jobID] = struct{}{}
		}
	}
	coveredJobs := make(map[int64]struct{})
	for _, spawn := range s.reservations {
		if spawn.Repo != repo || spawn.Phase != PhaseAssigned || spawn.AssignedJobID <= 0 {
			continue
		}
		if _, stillQueued := queued[spawn.AssignedJobID]; stillQueued {
			coveredJobs[spawn.AssignedJobID] = struct{}{}
		}
	}
	for jobID := range s.consumedJobs[repo] {
		if _, stillQueued := queued[jobID]; stillQueued {
			coveredJobs[jobID] = struct{}{}
			continue
		}
		delete(s.consumedJobs[repo], jobID)
	}
	if len(s.consumedJobs[repo]) == 0 {
		delete(s.consumedJobs, repo)
	}
	return coverage + len(coveredJobs)
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
	if s.draining || s.teardownBlocked {
		return false
	}
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

func (s *State) MarkAssigned(spawnID string, jobID int64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok || jobID <= 0 || (spawn.Phase != PhasePending && spawn.Phase != PhaseOnline) {
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
	spawn.AssignedJobID = jobID
	spawn.AssignedAt = now
	s.assignmentsTotal++
	return true
}

// MarkTeardownBlocked converts an active reservation into fail-closed capacity
// debt. It is idempotent so repeated teardown failures do not inflate counters.
func (s *State) MarkTeardownBlocked(spawnID, repo, detail string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok {
		r := s.ensure(repo)
		r.InFlight++
		r.TeardownBlocked++
		s.reservations[spawnID] = &SpawnState{
			SpawnID: spawnID, Repo: repo, Phase: PhaseTeardownBlocked,
			ReservedAt: at, TeardownBlockedAt: at, TeardownFailure: detail,
		}
		s.teardownBlocked = true
		s.teardownFailures++
		return true
	}
	if spawn.Phase == PhaseTeardownBlocked {
		spawn.TeardownFailure = detail
		return false
	}
	r := s.ensure(spawn.Repo)
	s.decrementPhaseLocked(r, spawn.Phase)
	r.TeardownBlocked++
	spawn.Phase = PhaseTeardownBlocked
	spawn.TeardownBlockedAt = at
	spawn.TeardownFailure = detail
	s.teardownBlocked = true
	s.teardownFailures++
	return true
}

// UpdateTeardownFailure records the latest exact-retry error without counting
// the same blocked reservation as a new failure.
func (s *State) UpdateTeardownFailure(spawnID, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spawn, ok := s.reservations[spawnID]; ok && spawn.Phase == PhaseTeardownBlocked {
		spawn.TeardownFailure = detail
	}
}

// ResolveTeardown releases a blocked reservation only after its exact backend
// teardown retry has succeeded.
func (s *State) ResolveTeardown(spawnID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok || spawn.Phase != PhaseTeardownBlocked {
		return false
	}
	s.releaseReservationLocked(spawnID)
	s.teardownReconciled++
	s.teardownBlocked = false
	for _, reservation := range s.reservations {
		if reservation.Phase == PhaseTeardownBlocked {
			s.teardownBlocked = true
			break
		}
	}
	return true
}

// SchedulingBlocked reports whether admission is globally stopped for drain
// or because at least one teardown debt has not been reconciled.
func (s *State) SchedulingBlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.draining || s.teardownBlocked
}

// ReleaseReservation removes ordinary capacity and its phase component exactly
// once. Teardown-blocked reservations deliberately require ResolveTeardown.
func (s *State) ReleaseReservation(spawnID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	spawn, ok := s.reservations[spawnID]
	if !ok || spawn.Phase == PhaseTeardownBlocked {
		return
	}
	s.releaseReservationLocked(spawnID)
}

func (s *State) releaseReservationLocked(spawnID string) {
	spawn := s.reservations[spawnID]
	r := s.ensure(spawn.Repo)
	if spawn.AssignedJobID > 0 {
		if s.consumedJobs[spawn.Repo] == nil {
			s.consumedJobs[spawn.Repo] = map[int64]struct{}{}
		}
		s.consumedJobs[spawn.Repo][spawn.AssignedJobID] = struct{}{}
	}
	if r.InFlight > 0 {
		r.InFlight--
	}
	s.decrementPhaseLocked(r, spawn.Phase)
	delete(s.reservations, spawnID)
}

func (s *State) decrementPhaseLocked(r *RepoState, phase SpawnPhase) {
	switch phase {
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
	case PhaseTeardownBlocked:
		if r.TeardownBlocked > 0 {
			r.TeardownBlocked--
		}
	}
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

// RecordRunnerOperationFailure records an unresolved runner-management
// capability failure independently from demand polling.
func (s *State) RecordRunnerOperationFailure(repo, operation, class, detail string) {
	s.mu.Lock()
	s.ensure(repo).RunnerOperationError[operation] = OperationError{
		Class: class, Detail: detail,
	}
	s.mu.Unlock()
}

// RecordRunnerOperationSuccess clears only the corresponding capability.
// This prevents a successful queue read (or a different runner API) from
// masking a permission failure that has not itself recovered.
func (s *State) RecordRunnerOperationSuccess(repo, operation string) {
	s.mu.Lock()
	delete(s.ensure(repo).RunnerOperationError, operation)
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

// AcquireSemaphores is retained for compatibility callers. Scheduler paths
// use TryReserve so pending work is visible before execution.
func (s *State) AcquireSemaphores(repo string, repoCap, globalCap int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining || s.teardownBlocked {
		return false
	}
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

func (s *State) SetRateLimited(paused bool) {
	s.mu.Lock()
	s.rateLimited = paused
	s.mu.Unlock()
}

// Snapshot is the complete operator-visible runtime state.
type Snapshot struct {
	PerRepo                 map[string]RepoState  `json:"per_repo"`
	Reservations            map[string]SpawnState `json:"reservations"`
	GlobalInFlight          int                   `json:"global_in_flight"`
	RateLimitRemaining      int                   `json:"rate_limit_remaining"`
	RateLimitLimit          int                   `json:"rate_limit_limit"`
	RateLimitReset          time.Time             `json:"rate_limit_reset"`
	RateLimited             bool                  `json:"rate_limited"`
	ConfiguredCapacity      int                   `json:"configured_capacity"`
	WorkerCapacity          int                   `json:"worker_capacity"`
	Version                 string                `json:"version"`
	BuildSHA                string                `json:"build_sha"`
	ConfigLoaded            bool                  `json:"config_loaded"`
	Draining                bool                  `json:"draining"`
	TeardownBlocked         bool                  `json:"teardown_blocked"`
	AssignmentsTotal        int64                 `json:"assignments_total"`
	CompletedTotal          int64                 `json:"completed_total"`
	UnassignedExitsTotal    int64                 `json:"unassigned_exits_total"`
	DeregistrationsTotal    int64                 `json:"deregistrations_total"`
	TeardownFailuresTotal   int64                 `json:"teardown_failures_total"`
	TeardownReconciledTotal int64                 `json:"teardown_reconciled_total"`
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		PerRepo:                 make(map[string]RepoState, len(s.perRepo)),
		Reservations:            make(map[string]SpawnState, len(s.reservations)),
		RateLimitRemaining:      s.rlRemaining,
		RateLimitLimit:          s.rlLimit,
		RateLimitReset:          s.rlReset,
		RateLimited:             s.rateLimited,
		ConfiguredCapacity:      s.configuredCapacity,
		WorkerCapacity:          s.workerCapacity,
		Version:                 s.version,
		BuildSHA:                s.buildSHA,
		ConfigLoaded:            s.configLoaded,
		Draining:                s.draining,
		TeardownBlocked:         s.teardownBlocked,
		AssignmentsTotal:        s.assignmentsTotal,
		CompletedTotal:          s.completedTotal,
		UnassignedExitsTotal:    s.unassignedTotal,
		DeregistrationsTotal:    s.deregisteredTotal,
		TeardownFailuresTotal:   s.teardownFailures,
		TeardownReconciledTotal: s.teardownReconciled,
	}
	for repo, r := range s.perRepo {
		repoCopy := *r
		if r.RunnerOperationError != nil {
			repoCopy.RunnerOperationError = make(map[string]OperationError, len(r.RunnerOperationError))
			for operation, operationErr := range r.RunnerOperationError {
				repoCopy.RunnerOperationError[operation] = operationErr
			}
		}
		snap.PerRepo[repo] = repoCopy
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
