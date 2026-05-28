package cornerstone

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuilder_SpawnStarted_HasContainerContext(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))

	require.NoError(t, em.EmitSpawnStarted(SpawnStartedFields{
		Scope:         "datacentric",
		Repo:          "NaorPenso/datacentric",
		SpawnID:       "01HXG",
		ContainerName: "rs-datacentric-job-3",
		ImageDigest:   "sha256:abc",
	}))

	var got map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got))
	require.Equal(t, EventSpawnStarted, got["event.sub.type"])
	require.Equal(t, "Change", got["event.type"])
	require.Contains(t, got, "container.context")
	cc := got["container.context"].(map[string]any)
	require.Equal(t, "rs-datacentric-job-3", cc["container.name"])
	require.Equal(t, "sha256:abc", cc["container.image.digest"])

	details := got["event.details"].(map[string]any)
	tags := details["tags"].([]any)
	require.Contains(t, tags, "scope:datacentric")
	require.Contains(t, tags, "repo:NaorPenso/datacentric")
}

// Covers builder.go:133 — ExtraErrorData merging into error.data.
func TestBuilder_SpawnFailed_WithExtraErrorData(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitSpawnFailed(SpawnFailedFields{
		Scope: "s", Repo: "o/r", SpawnID: "i",
		FailureReason: "boom",
		Detail:        "primary detail",
		ExtraErrorData: map[string]any{
			"http_status": 500,
			"endpoint":    "queue",
		},
	}))
	require.Contains(t, buf.String(), `"http_status":500`)
	require.Contains(t, buf.String(), `"endpoint":"queue"`)
}

func TestBuilder_SpawnFailed_CarriesFailureReason(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))

	require.NoError(t, em.EmitSpawnFailed(SpawnFailedFields{
		Scope:         "s",
		Repo:          "o/r",
		SpawnID:       "i",
		FailureReason: "socket_proxy_403_capadd_denied",
		Detail:        "HostConfig.CapAdd contained NET_ADMIN",
	}))

	require.Contains(t, buf.String(), `"failure.reason":"socket_proxy_403_capadd_denied"`)
	require.Contains(t, buf.String(), `"detail":"HostConfig.CapAdd contained NET_ADMIN"`)
}

func TestBuilder_PollTick_RateLimitContextPresent(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))

	require.NoError(t, em.EmitPollTick(PollTickFields{
		Scope:              "s",
		RateLimitRemaining: 4823,
		RateLimitLimit:     5000,
		RateLimitResetISO:  "2026-05-19T11:00:00Z",
	}))

	require.True(t, strings.Contains(buf.String(), `"rate.limit.context"`))
}

func TestBuilder_SpawnCompleted_CarriesExitCode(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))

	require.NoError(t, em.EmitSpawnCompleted(SpawnCompletedFields{
		Scope: "s", Repo: "o/r", SpawnID: "i",
		ContainerID: "abc", ContainerName: "n",
		ImageDigest: "sha256:zz", ExitCode: 0, DurationMillis: 1234,
	}))
	var got Event
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got))
	require.NotNil(t, got.ContainerContext.ExitCode)
	require.Equal(t, 0, *got.ContainerContext.ExitCode)
}

func TestBuilder_SpawnTimeout_CarriesElapsedAndCap(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitSpawnTimeoutForcedTeardown(SpawnTimeoutForcedTeardownFields{
		Scope: "s", Repo: "o/r", SpawnID: "i",
		ContainerName: "n", ConfiguredTimeoutSecs: 600, ElapsedSeconds: 605,
	}))
	require.Contains(t, buf.String(), `"configured_timeout_seconds":600`)
	require.Contains(t, buf.String(), `"elapsed_seconds":605`)
}

func TestBuilder_RunnerLeakCleaned_AuditContext(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitRunnerLeakCleaned(RunnerLeakCleanedFields{
		Scope: "s", Repo: "o/r", SpawnID: "i", GitHubRunnerID: 42,
	}))
	require.Contains(t, buf.String(), `"audit.action":"github_runner_delete"`)
	require.Contains(t, buf.String(), `"audit.resource.id":"42"`)
}

func TestBuilder_BreakerEvents(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitBreakerOpened(BreakerFields{Scope: "s", Repo: "o/r", ConsecutiveFailures: 5}))
	require.NoError(t, em.EmitBreakerClosed(BreakerFields{Scope: "s", Repo: "o/r"}))
	require.Contains(t, buf.String(), `"consecutive_failures":5`)
	require.Contains(t, buf.String(), EventBreakerClosed)
}

func TestBuilder_Ratelimit(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitRatelimitPaused(RateLimitFields{Scope: "s", Remaining: 0, Limit: 5000, ResetISO: "2026-05-19T11:00:00Z"}))
	require.NoError(t, em.EmitRatelimitResumed(RateLimitFields{Scope: "s", Remaining: 5000, Limit: 5000, ResetISO: "2026-05-19T12:00:00Z"}))
	require.Contains(t, buf.String(), EventRatelimitPaused)
	require.Contains(t, buf.String(), EventRatelimitResumed)
}

func TestBuilder_RemainingEvents(t *testing.T) {
	var buf bytes.Buffer
	em := NewEmitter(&buf, FixedClock("t"), FixedUUID("u"))
	require.NoError(t, em.EmitSpawnJITAcquired(SpawnJITAcquiredFields{Scope: "s", Repo: "o/r", SpawnID: "i", ContainerName: "n", GitHubRunnerID: 1}))
	require.NoError(t, em.EmitSpawnRunnerCreated(SpawnRunnerCreatedFields{Scope: "s", Repo: "o/r", SpawnID: "i", ContainerName: "n", ImageDigest: "sha256:z", NetworkName: "rs-net-x"}))
	require.NoError(t, em.EmitPollQueuedJobsObserved(PollQueuedJobsObservedFields{Scope: "s", Repo: "o/r", Count: 3}))
	require.NoError(t, em.EmitDriftReconciled(DriftReconciledFields{Scope: "s", Repo: "o/r", Delta: -1}))
	require.NoError(t, em.EmitAuthDegraded(AuthDegradedFields{Scope: "s", Repo: "o/r", Status: 401}))
	require.NoError(t, em.EmitConfigReloaded(ConfigReloadedFields{Scope: "s"}))
	require.NoError(t, em.EmitConfigInvalid(ConfigInvalidFields{Scope: "s", Path: "/x", FailureReason: "missing_field"}))
	require.NoError(t, em.EmitHealthProbe())
	for _, name := range []string{
		EventSpawnJITAcquired, EventSpawnRunnerCreated, EventPollQueuedJobsObserved,
		EventDriftReconciled, EventAuthDegraded, EventConfigReloaded,
		EventConfigInvalid, EventHealthProbe,
	} {
		require.Contains(t, buf.String(), name)
	}
}
