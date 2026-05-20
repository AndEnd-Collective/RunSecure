package cornerstone

import "fmt"

// One typed constructor per registered event name. Each constructor populates
// the required_contexts declared in the registry YAML and the appropriate
// severity from §9.1 of the design.
//
// Pattern:
//   - <EventName>Fields struct documents inputs.
//   - Emit<EventName>(f) constructs the Event and calls Emit().
//
// Returning an error preserves the structural-floor property: if an event
// fails validation it is NOT written (no partial telemetry).

type SpawnStartedFields struct {
	Scope         string
	Repo          string
	SpawnID       string
	ContainerName string
	ImageDigest   string
}

func (e *Emitter) EmitSpawnStarted(f SpawnStartedFields) error {
	return e.Emit(Event{
		EventSubType: EventSpawnStarted,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:  "spawn intent acquired semaphores",
			Severity: 6,
			Result:   ResultSuccess,
			Status:   StatusStarted,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{
			Name:        f.ContainerName,
			ImageDigest: f.ImageDigest,
			Runtime:     "docker",
		},
	})
}

type SpawnJITAcquiredFields struct {
	Scope, Repo, SpawnID string
	ContainerName        string
	GitHubRunnerID       int64
}

func (e *Emitter) EmitSpawnJITAcquired(f SpawnJITAcquiredFields) error {
	return e.Emit(Event{
		EventSubType: EventSpawnJITAcquired,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:  fmt.Sprintf("JIT config acquired (runner id %d)", f.GitHubRunnerID),
			Severity: 6,
			Result:   ResultSuccess,
			Status:   StatusInProgress,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{Name: f.ContainerName, Runtime: "docker"},
	})
}

type SpawnRunnerCreatedFields struct {
	Scope, Repo, SpawnID string
	ContainerName        string
	ImageDigest          string
	NetworkName          string
}

func (e *Emitter) EmitSpawnRunnerCreated(f SpawnRunnerCreatedFields) error {
	return e.Emit(Event{
		EventSubType: EventSpawnRunnerCreated,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:  "spawn stack created on isolated network",
			Severity: 6,
			Result:   ResultSuccess,
			Status:   StatusInProgress,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{Name: f.ContainerName, ImageDigest: f.ImageDigest, Runtime: "docker"},
		NetworkContext:   &NetworkContext{Name: f.NetworkName, Driver: "bridge"},
	})
}

type SpawnCompletedFields struct {
	Scope, Repo, SpawnID string
	ContainerID          string
	ContainerName        string
	ImageDigest          string
	ExitCode             int
	DurationMillis       int64
}

func (e *Emitter) EmitSpawnCompleted(f SpawnCompletedFields) error {
	ec := f.ExitCode
	return e.Emit(Event{
		EventSubType: EventSpawnCompleted,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:  "ephemeral runner completed job",
			Severity: 6,
			Result:   ResultSuccess,
			Status:   StatusCompleted,
			Duration: f.DurationMillis,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{
			ID: f.ContainerID, Name: f.ContainerName,
			ImageDigest: f.ImageDigest, Runtime: "docker", ExitCode: &ec,
		},
	})
}

type SpawnFailedFields struct {
	Scope, Repo, SpawnID string
	ContainerName        string
	FailureReason        string         // short snake_case stable code
	Detail               string         // free-form context (goes into error.data.detail)
	ExtraErrorData       map[string]any // optional additional structured context
}

func (e *Emitter) EmitSpawnFailed(f SpawnFailedFields) error {
	ed := map[string]any{}
	if f.Detail != "" {
		ed["detail"] = f.Detail
	}
	for k, v := range f.ExtraErrorData {
		ed[k] = v
	}
	return e.Emit(Event{
		EventSubType: EventSpawnFailed,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:       "spawn failed",
			Severity:      3,
			Result:        ResultFailure,
			FailureReason: f.FailureReason,
			ErrorData:     ed,
			Status:        StatusFailed,
			Tags:          scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{Name: f.ContainerName, Runtime: "docker"},
	})
}

type SpawnTimeoutForcedTeardownFields struct {
	Scope, Repo, SpawnID  string
	ContainerName         string
	ConfiguredTimeoutSecs int
	ElapsedSeconds        int
}

func (e *Emitter) EmitSpawnTimeoutForcedTeardown(f SpawnTimeoutForcedTeardownFields) error {
	return e.Emit(Event{
		EventSubType: EventSpawnTimeoutForcedTeardown,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:       "spawn force-torn-down after wall-clock timeout",
			Severity:      4,
			Result:        ResultFailure,
			FailureReason: "wall_clock_timeout",
			ErrorData: map[string]any{
				"configured_timeout_seconds": f.ConfiguredTimeoutSecs,
				"elapsed_seconds":            f.ElapsedSeconds,
			},
			Status: StatusFailed,
			Tags:   scopeRepoTags(f.Scope, f.Repo),
		},
		ContainerContext: &ContainerContext{Name: f.ContainerName, Runtime: "docker"},
	})
}

type RunnerLeakCleanedFields struct {
	Scope, Repo, SpawnID string
	GitHubRunnerID       int64
}

func (e *Emitter) EmitRunnerLeakCleaned(f RunnerLeakCleanedFields) error {
	return e.Emit(Event{
		EventSubType: EventRunnerLeakCleaned,
		EventType:    EventTypeChange,
		TraceID:      "spawn-" + f.SpawnID,
		EventDetails: EventDetails{
			Summary:  "cleaned up orphan GitHub runner registration",
			Severity: 5,
			Result:   ResultSuccess,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
		AuditContext: &AuditContext{
			Action:       "github_runner_delete",
			ResourceType: "github_runner",
			ResourceID:   fmt.Sprintf("%d", f.GitHubRunnerID),
		},
	})
}

type BreakerFields struct {
	Scope, Repo         string
	ConsecutiveFailures int
}

func (e *Emitter) EmitBreakerOpened(f BreakerFields) error {
	return e.Emit(Event{
		EventSubType: EventBreakerOpened,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:  "circuit breaker opened",
			Severity: 4,
			Result:   ResultSuccess,
			ErrorData: map[string]any{
				"consecutive_failures": f.ConsecutiveFailures,
			},
			Tags: scopeRepoTags(f.Scope, f.Repo),
		},
	})
}

func (e *Emitter) EmitBreakerClosed(f BreakerFields) error {
	return e.Emit(Event{
		EventSubType: EventBreakerClosed,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:  "circuit breaker closed",
			Severity: 6,
			Result:   ResultSuccess,
			Tags:     scopeRepoTags(f.Scope, f.Repo),
		},
	})
}

type RateLimitFields struct {
	Scope     string
	Remaining int
	Limit     int
	ResetISO  string
}

func (e *Emitter) EmitRatelimitPaused(f RateLimitFields) error {
	return e.Emit(Event{
		EventSubType: EventRatelimitPaused,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:  "API rate-limit exhausted; pausing scope",
			Severity: 4,
			Result:   ResultSuccess,
			Tags:     []string{"scope:" + f.Scope},
		},
		RateLimitContext: &RateLimitContext{Remaining: f.Remaining, Limit: f.Limit, ResetISO: f.ResetISO},
	})
}

func (e *Emitter) EmitRatelimitResumed(f RateLimitFields) error {
	return e.Emit(Event{
		EventSubType: EventRatelimitResumed,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:  "rate-limit window cleared; resuming scope",
			Severity: 6,
			Result:   ResultSuccess,
			Tags:     []string{"scope:" + f.Scope},
		},
		RateLimitContext: &RateLimitContext{Remaining: f.Remaining, Limit: f.Limit, ResetISO: f.ResetISO},
	})
}

type PollTickFields struct {
	Scope              string
	RateLimitRemaining int
	RateLimitLimit     int
	RateLimitResetISO  string
}

func (e *Emitter) EmitPollTick(f PollTickFields) error {
	return e.Emit(Event{
		EventSubType: EventPollTick,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{
			Summary:  "poll cycle tick",
			Severity: 7,
			Result:   ResultSuccess,
			Tags:     []string{"scope:" + f.Scope},
		},
		RateLimitContext: &RateLimitContext{
			Remaining: f.RateLimitRemaining, Limit: f.RateLimitLimit, ResetISO: f.RateLimitResetISO,
		},
	})
}

type PollQueuedJobsObservedFields struct {
	Scope, Repo string
	Count       int
}

func (e *Emitter) EmitPollQueuedJobsObserved(f PollQueuedJobsObservedFields) error {
	return e.Emit(Event{
		EventSubType: EventPollQueuedJobsObserved,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{
			Summary:   fmt.Sprintf("%d queued jobs observed", f.Count),
			Severity:  6,
			Result:    ResultSuccess,
			ErrorData: map[string]any{"queued_count": f.Count},
			Tags:      scopeRepoTags(f.Scope, f.Repo),
		},
	})
}

type DriftReconciledFields struct {
	Scope, Repo string
	Delta       int
}

func (e *Emitter) EmitDriftReconciled(f DriftReconciledFields) error {
	return e.Emit(Event{
		EventSubType: EventDriftReconciled,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:   "drift reconciled against docker state",
			Severity:  5,
			Result:    ResultSuccess,
			ErrorData: map[string]any{"delta": f.Delta},
			Tags:      scopeRepoTags(f.Scope, f.Repo),
		},
		AuditContext: &AuditContext{Action: "drift_reconcile", ResourceType: "in_flight_counter"},
	})
}

type AuthDegradedFields struct {
	Scope  string
	Repo   string // empty if scope-wide
	Status int    // HTTP status (401/403)
}

func (e *Emitter) EmitAuthDegraded(f AuthDegradedFields) error {
	tags := []string{"scope:" + f.Scope}
	if f.Repo != "" {
		tags = append(tags, "repo:"+f.Repo)
	}
	return e.Emit(Event{
		EventSubType: EventAuthDegraded,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{
			Summary:       "PAT auth degraded",
			Severity:      3,
			Result:        ResultFailure,
			FailureReason: "github_auth_rejected",
			ErrorData:     map[string]any{"http_status": f.Status},
			Tags:          tags,
		},
	})
}

type ConfigReloadedFields struct{ Scope string }

func (e *Emitter) EmitConfigReloaded(f ConfigReloadedFields) error {
	return e.Emit(Event{
		EventSubType: EventConfigReloaded,
		EventType:    EventTypeChange,
		EventDetails: EventDetails{
			Summary:  "PAT secret reloaded from disk",
			Severity: 6,
			Result:   ResultSuccess,
			Tags:     []string{"scope:" + f.Scope},
		},
		AuditContext: &AuditContext{Action: "pat_rotated", ResourceType: "credential"},
	})
}

type ConfigInvalidFields struct {
	Scope         string
	Path          string
	FailureReason string
}

func (e *Emitter) EmitConfigInvalid(f ConfigInvalidFields) error {
	return e.Emit(Event{
		EventSubType: EventConfigInvalid,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{
			Summary:       "config invalid",
			Severity:      3,
			Result:        ResultFailure,
			FailureReason: f.FailureReason,
			ErrorData:     map[string]any{"path": f.Path},
			Tags:          []string{"scope:" + f.Scope},
		},
	})
}

func (e *Emitter) EmitHealthProbe() error {
	return e.Emit(Event{
		EventSubType: EventHealthProbe,
		EventType:    EventTypeActivity,
		EventDetails: EventDetails{
			Summary:  "/healthz probe",
			Severity: 7,
			Result:   ResultSuccess,
		},
	})
}

func scopeRepoTags(scope, repo string) []string {
	return []string{"scope:" + scope, "repo:" + repo}
}
