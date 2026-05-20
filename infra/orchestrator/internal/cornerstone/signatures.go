package cornerstone

// ProjectSignature is the value emitted in event.signature on every event.
// Bumping this is a breaking change for consumers (SIEM rules, dashboards).
const ProjectSignature = "runsecure-orchestrator-v1"

// Event names — must match .cornerstone/events/<name>.yaml exactly.
//
// To add a new event:
//  1. Add a constant here.
//  2. Add a .cornerstone/events/<name>.yaml file with a fresh UUID.
//  3. Add it to AllEventNames() below.
//  4. Add a typed constructor to builder.go.
const (
	EventPollTick                   = "runsecure.orchestrator.poll.tick"
	EventPollQueuedJobsObserved     = "runsecure.orchestrator.poll.queued_jobs_observed"
	EventSpawnStarted               = "runsecure.orchestrator.spawn.started"
	EventSpawnJITAcquired           = "runsecure.orchestrator.spawn.jit_acquired"
	EventSpawnRunnerCreated         = "runsecure.orchestrator.spawn.runner_created"
	EventSpawnCompleted             = "runsecure.orchestrator.spawn.completed"
	EventSpawnFailed                = "runsecure.orchestrator.spawn.failed"
	EventSpawnTimeoutForcedTeardown = "runsecure.orchestrator.spawn.timeout_forced_teardown"
	EventRunnerLeakCleaned          = "runsecure.orchestrator.runner.leak_cleaned"
	EventBreakerOpened              = "runsecure.orchestrator.breaker.opened"
	EventBreakerClosed              = "runsecure.orchestrator.breaker.closed"
	EventRatelimitPaused            = "runsecure.orchestrator.ratelimit.paused"
	EventRatelimitResumed           = "runsecure.orchestrator.ratelimit.resumed"
	EventDriftReconciled            = "runsecure.orchestrator.drift.reconciled"
	EventAuthDegraded               = "runsecure.orchestrator.auth.degraded"
	EventConfigReloaded             = "runsecure.orchestrator.config.reloaded"
	EventConfigInvalid              = "runsecure.orchestrator.config.invalid"
	EventHealthProbe                = "runsecure.orchestrator.health.probe"
)

// AllEventNames returns every registered event name. The test in
// signatures_test.go asserts each has a registry YAML file.
func AllEventNames() []string {
	return []string{
		EventPollTick,
		EventPollQueuedJobsObserved,
		EventSpawnStarted,
		EventSpawnJITAcquired,
		EventSpawnRunnerCreated,
		EventSpawnCompleted,
		EventSpawnFailed,
		EventSpawnTimeoutForcedTeardown,
		EventRunnerLeakCleaned,
		EventBreakerOpened,
		EventBreakerClosed,
		EventRatelimitPaused,
		EventRatelimitResumed,
		EventDriftReconciled,
		EventAuthDegraded,
		EventConfigReloaded,
		EventConfigInvalid,
		EventHealthProbe,
	}
}
