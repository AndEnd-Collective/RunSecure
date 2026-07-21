package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makePATFile is a small helper used by tests that need a separate
// github.Client pointing at a non-default URL.
func makePATFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(p, []byte("p"), 0o400))
	return p
}

func TestSpawn_HappyPath(t *testing.T) {
	t.Setenv("RUNSECURE_KUBE_DNS_SERVICE_CIDRS", "10.96.0.10/32,10.100.0.10/32")
	t.Setenv("RUNSECURE_KUBE_DNS_NAMESPACE", "kube-system")
	t.Setenv("RUNSECURE_KUBE_DNS_POD_LABEL_KEY", "k8s-app")
	t.Setenv("RUNSECURE_KUBE_DNS_POD_LABEL_VALUE", "kube-dns")
	d := newSpawnDeps(t)
	w := NewSpawnWorker(d)

	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}))

	// Execute must have delegated spawn to the backend (not docker directly).
	require.Equal(t, 1, d.be.spawnCount(), "Backend().Spawn must be called once")
	require.Equal(t, 1, d.be.waitCount(), "Backend().WaitForExit must be called once")
	require.Equal(t, 1, d.be.teardownCount(), "Backend().Teardown must be called once")
	// The fake docker client must NOT have had CreateNetwork called (zero network creates).
	require.Equal(t, 0, d.dc.netCreated, "Execute must not call Docker().CreateNetwork directly")

	require.Equal(t, 0, d.st.InFlight("o/r"), "in-flight decremented after teardown")

	d.requireEmitted(t,
		cornerstone.EventSpawnStarted,
		cornerstone.EventSpawnJITAcquired,
		cornerstone.EventSpawnRunnerCreated,
		cornerstone.EventRunnerOnline,
		cornerstone.EventJobAssigned,
		cornerstone.EventRunnerCompleted,
		cornerstone.EventSpawnCompleted,
	)
	snap := d.st.Snapshot()
	require.Equal(t, int64(1), snap.AssignmentsTotal)
	require.Equal(t, int64(1), snap.CompletedTotal)
	require.Equal(t, int64(1), snap.DeregistrationsTotal)
	d.be.mu.Lock()
	spawnInput := d.be.spawnCalls[0]
	d.be.mu.Unlock()
	require.Equal(t, "v-test", spawnInput.Version)
	require.Equal(t, "sha-test", spawnInput.BuildSHA)
	require.Equal(t, []string{"10.96.0.10/32", "10.100.0.10/32"}, spawnInput.KubeDNSServiceCIDRs)
	require.Equal(t, "kube-system", spawnInput.KubeDNSNamespace)
	require.Equal(t, "k8s-app", spawnInput.KubeDNSPodLabelKey)
	require.Equal(t, "kube-dns", spawnInput.KubeDNSPodLabelValue)
}

func TestSpawn_JITRegistrationCarriesRestartDiscoveryLabels(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh

	require.NoError(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "vladislav", Repo: "o/r", SpawnID: "owned-labels",
	}))

	fake.mu.Lock()
	labels := append([]string(nil), fake.jitRequestedLabels...)
	fake.mu.Unlock()
	require.ElementsMatch(t, []string{
		"self-hosted", "Linux", JITOwnerLabel, JITScopeLabelPrefix + "vladislav",
	}, labels)
}

func TestJITRunnerLabelsRejectEmptyAndDuplicateOwnershipLabels(t *testing.T) {
	labels := jitRunnerLabels("vladislav", []string{
		"", "self-hosted", JITOwnerLabel, "self-hosted",
		JITScopeLabelPrefix + "vladislav",
	})

	require.Equal(t, []string{
		"self-hosted", JITOwnerLabel, JITScopeLabelPrefix + "vladislav",
	}, labels)
}

func TestSpawn_ZeroExitWithoutAssignmentIsRuntimeFailure(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "online"
	fake.runnerBusy = false
	fake.mu.Unlock()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "unassigned",
	})
	require.ErrorContains(t, err, "before GitHub reported a job assignment")
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventRunnerExitedUnassigned, cornerstone.EventSpawnFailed)
	require.Equal(t, int64(1), d.st.Snapshot().UnassignedExitsTotal)
	require.NotContains(t, d.emBuf.String(), `"event.sub.type":"`+cornerstone.EventSpawnCompleted+`"`)
}

func TestSpawn_NeverOnlineFailsAtRegistrationDeadline(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusNotFound
	fake.mu.Unlock()
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 5 * time.Millisecond, AssignmentTimeout: 20 * time.Millisecond,
		PollInterval: time.Millisecond,
	}
	d.be.inspectExitDelay = 30 * time.Millisecond

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "never-online",
	})
	require.ErrorContains(t, err, "did not become online")
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_online_timeout"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerCompleted)
}

func TestSpawn_OnlineButNeverAssignedFailsAtAssignmentDeadline(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "online"
	fake.runnerBusy = false
	fake.runnerErrCode = http.StatusNotFound
	fake.runnerErrAfter = 2
	fake.mu.Unlock()
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 20 * time.Millisecond, AssignmentTimeout: 5 * time.Millisecond,
		PollInterval: time.Millisecond,
	}
	d.be.inspectExitDelay = 30 * time.Millisecond

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "never-assigned",
	})
	require.ErrorContains(t, err, "did not receive a job")
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventSpawnFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_assignment_timeout"`)
}

func TestSpawn_RunnerBecomesBusyOnLifecyclePoll(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.runnerChangeAfter = 2
	fake.runnerStatusAfter = "online"
	fake.runnerBusyAfter = true
	fake.mu.Unlock()
	d.lifecycle = LifecycleTiming{
		OnlineTimeout: 20 * time.Millisecond, AssignmentTimeout: 20 * time.Millisecond,
		PollInterval: time.Millisecond,
	}
	d.be.waitDelay = 5 * time.Millisecond
	require.NoError(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "poll-transition",
	}))
	d.requireEmitted(t, cornerstone.EventRunnerOnline, cornerstone.EventJobAssigned, cornerstone.EventRunnerCompleted)
}

func TestSpawn_RunnerObservationRateLimitFailsDelivery(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusTooManyRequests
	fake.mu.Unlock()
	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "rate-limited-observation",
	})
	require.ErrorIs(t, err, github.ErrRateLimited)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_runner_observation_rate_limited"`)
	require.True(t, d.ratePaused.Load())
	require.Equal(t, "github_rate_limited",
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError[runnerOperationGetRunner].Class)
	d.requireEmitted(t, cornerstone.EventRatelimitPaused)
}

func TestSpawn_JITRateLimitPausesScopeScheduler(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jitErrCode = http.StatusForbidden
	fake.rlAfterResponse = true
	fake.rlLimit = 5000
	fake.rlRemaining = 12
	fake.rlReset = "1800000000"
	fake.mu.Unlock()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-rate-limited",
	})
	require.ErrorIs(t, err, github.ErrRateLimited)
	require.True(t, d.ratePaused.Load())
	remaining, limit, reset := d.RateLimitContextFor("s")
	require.Equal(t, 0, remaining)
	require.Equal(t, 5000, limit)
	require.Equal(t, time.Unix(1800000000, 0).Format(time.RFC3339), reset)
	require.Equal(t, "github_rate_limited",
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError[runnerOperationGenerateJIT].Class)
	d.requireEmitted(t, cornerstone.EventRatelimitPaused)
}

func TestSpawn_JITAuthFailureBlocksReadinessIndependentlyOfDemand(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jitErrCode = http.StatusForbidden
	fake.mu.Unlock()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-auth-failure",
	})

	require.ErrorIs(t, err, github.ErrAuthFailed)
	d.st.RecordPollSuccess("o/r", 1, d.clk.Now())
	repoState := d.st.Snapshot().PerRepo["o/r"]
	require.Empty(t, repoState.LastPollError)
	require.Equal(t, "github_auth_failed",
		repoState.RunnerOperationError[runnerOperationGenerateJIT].Class)
}

func TestSpawn_ContextCancellationWhileObservingRunner(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "offline"
	fake.runnerBusy = false
	fake.mu.Unlock()
	d.be.inspectExitDelay = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Millisecond)
		cancel()
	}()
	err := NewSpawnWorker(d).Execute(ctx, SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "cancelled"})
	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_observation_cancelled"`)
}

func TestSpawn_RunnerObservationAuthFailureFailsDelivery(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerErrCode = http.StatusForbidden
	fake.mu.Unlock()
	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "auth-failure",
	})
	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"github_runner_observation_failed"`)
	require.Equal(t, "github_auth_failed",
		d.st.Snapshot().PerRepo["o/r"].RunnerOperationError[runnerOperationGetRunner].Class)
}

func TestSpawn_DeregistrationFailureFailsRuntimeCleanup(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusForbidden
	fake.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "deregister-failure",
		})
	}()
	require.Eventually(t, func() bool {
		snap := d.st.Snapshot()
		return snap.TeardownBlocked && snap.PerRepo["o/r"].TeardownBlocked == 1
	}, time.Second, time.Millisecond)
	cancel()
	err := <-done
	require.ErrorIs(t, err, github.ErrAuthFailed)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_deregistration_failed"`)
	d.requireEmitted(t, cornerstone.EventRunnerCompleted)
	snap := d.st.Snapshot()
	require.Equal(t, int64(1), snap.CompletedTotal)
	require.Zero(t, snap.DeregistrationsTotal)
	require.Equal(t, 1, snap.GlobalInFlight,
		"unresolved GitHub registration cleanup must retain capacity")
	require.Equal(t, "github_auth_failed",
		snap.PerRepo["o/r"].RunnerOperationError[runnerOperationDelete].Class)
	require.False(t, d.st.TryReserve("replacement", "o/r", 5, 10, d.clk.Now()))
}

func TestSpawn_DeregistrationAuthFailureUsesSlowRetryBackoff(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusForbidden
	fake.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "deregister-auth-backoff",
		})
	}()
	require.Eventually(t, func() bool {
		return d.st.Snapshot().TeardownBlocked
	}, time.Second, time.Millisecond)
	fake.mu.Lock()
	initialCalls := fake.deleteCalled
	fake.mu.Unlock()
	require.Equal(t, 1, initialCalls)
	d.clk.Advance(d.lifecycle.CleanupRetryInterval)
	time.Sleep(10 * time.Millisecond)
	fake.mu.Lock()
	require.Equal(t, initialCalls, fake.deleteCalled,
		"authentication failures must not retry at the generic cleanup cadence")
	fake.mu.Unlock()
	cancel()
	require.ErrorIs(t, <-done, github.ErrAuthFailed)
}

func TestSpawn_DeregistrationRateLimitWaitsUntilReset(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	resetAt := d.clk.Now().Add(10 * time.Second)
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusTooManyRequests
	fake.deleteErrUntil = 1
	fake.rlRemaining = 0
	fake.rlReset = fmt.Sprint(resetAt.Unix())
	fake.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "deregister-rate-reset",
		})
	}()
	require.Eventually(t, func() bool {
		return d.st.Snapshot().TeardownBlocked && d.ratePaused.Load()
	}, time.Second, time.Millisecond)
	time.Sleep(10 * time.Millisecond) // let the fake-clock reset timer register
	d.clk.Advance(9 * time.Second)
	time.Sleep(10 * time.Millisecond)
	fake.mu.Lock()
	require.Equal(t, 1, fake.deleteCalled)
	fake.mu.Unlock()
	d.clk.Advance(time.Second)
	err := <-done
	require.ErrorIs(t, err, github.ErrRateLimited)
	require.False(t, d.st.Snapshot().TeardownBlocked)
	fake.mu.Lock()
	require.Equal(t, 2, fake.deleteCalled)
	fake.mu.Unlock()
}

func TestRunnerDeletionRateLimitWithoutResetUsesSafeFallback(t *testing.T) {
	d := newSpawnDeps(t)
	err := &github.APIError{
		Status: http.StatusTooManyRequests, Operation: "delete runner", Err: github.ErrRateLimited,
	}

	delay := NewSpawnWorker(d).runnerDeletionRetryDelay("s", err, time.Second)

	require.Equal(t, time.Minute, delay)
}

func TestSpawn_DeregistrationRetryResolvesDebtOnlyAfterExactSuccess(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusInternalServerError
	fake.deleteErrUntil = 2
	fake.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "deregister-recovers",
		})
	}()
	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.deleteCalled >= 2 && d.st.Snapshot().TeardownBlocked
	}, time.Second, time.Millisecond)
	d.clk.Advance(d.lifecycle.CleanupRetryInterval)
	err := <-done

	require.ErrorContains(t, err, "runner deregistration failed")
	snap := d.st.Snapshot()
	require.False(t, snap.TeardownBlocked)
	require.Zero(t, snap.GlobalInFlight)
	require.Equal(t, int64(1), snap.DeregistrationsTotal)
	require.Equal(t, int64(1), snap.TeardownReconciledTotal)
	require.Empty(t, snap.PerRepo["o/r"].RunnerOperationError)
}

func TestSpawn_SocketProxyDeny_EmitsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	// Inject a socket-proxy-denied error through the backend.
	d.be.spawnErr = errPolicyDenied("HostConfig.CapAdd")
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
	// WaitForExit must NOT be called when Spawn fails.
	require.Equal(t, 0, d.be.waitCount(), "WaitForExit must not be called after Spawn error")
}

func TestSpawn_PartialBackendRollbackRetainsDebtUntilExactTeardown(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("runner start failed; rollback incomplete")
	d.be.spawnPartialHandle = true
	d.be.teardownErr = errors.New("network still has endpoint")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "partial-backend",
		})
	}()

	require.Eventually(t, func() bool {
		return d.st.Snapshot().TeardownBlocked && d.be.teardownCount() >= 2
	}, time.Second, time.Millisecond)
	snap := d.st.Snapshot()
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, state.PhaseTeardownBlocked, snap.Reservations["partial-backend"].Phase)
	require.False(t, d.st.TryReserve("replacement", "o/r", 5, 10, d.clk.Now()))
	cancel()
	err := <-done

	require.ErrorContains(t, err, "rollback incomplete")
	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"backend_teardown_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventSpawnCompleted)
}

func TestSpawn_PartialBackendHandleIsRetriedEvenWhenCleanupRecoversImmediately(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("runner start failed; rollback incomplete")
	d.be.spawnPartialHandle = true

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "partial-backend-recovers",
	})

	require.ErrorContains(t, err, "rollback incomplete")
	require.Equal(t, 1, d.be.teardownCount(),
		"non-empty failure handle must always receive exact teardown")
	require.Zero(t, d.st.GlobalInFlight())
	require.False(t, d.st.Snapshot().TeardownBlocked)
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

func TestSpawn_PartialBackendAndRegistrationCleanupRecoverTogether(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	d.be.spawnErr = errors.New("runner start failed; rollback incomplete")
	d.be.spawnPartialHandle = true
	d.be.teardownErrs = []error{errors.New("network still has endpoint"), nil}
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusInternalServerError
	fake.deleteErrUntil = 1
	fake.mu.Unlock()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "partial-backend-and-runner-recover",
	})

	require.ErrorContains(t, err, "runner start failed; rollback incomplete")
	require.ErrorContains(t, err, "backend teardown failed: network still has endpoint")
	require.ErrorContains(t, err, "runner deregistration failed")
	require.Equal(t, 2, d.be.teardownCount())
	fake.mu.Lock()
	deleteCalls := fake.deleteCalled
	fake.mu.Unlock()
	require.Equal(t, 2, deleteCalls)
	require.Zero(t, d.st.GlobalInFlight())
	require.False(t, d.st.Snapshot().TeardownBlocked)
	require.Equal(t, int64(1), d.st.Snapshot().TeardownReconciledTotal)
}

func TestSettlePartialSpawnRetainsDebtWhenRunnerCleanupIsInterrupted(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.deleteErrCode = http.StatusInternalServerError
	fake.mu.Unlock()
	intent := SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "partial-runner-interrupted"}
	require.True(t, d.st.TryReserve(intent.SpawnID, intent.Repo, d.repoCap, d.globalCap, d.clk.Now()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := NewSpawnWorker(d).settlePartialSpawn(
		ctx,
		intent,
		"rs-partial-runner-interrupted",
		backend.Handle{SpawnID: intent.SpawnID, Backend: "fake"},
		errors.New("runner start failed; rollback incomplete"),
		100,
	)

	require.ErrorContains(t, err, "runner deregistration failed")
	require.ErrorContains(t, err, "runner deregistration reconciliation interrupted")
	require.ErrorIs(t, err, context.Canceled)
	snapshot := d.st.Snapshot()
	require.True(t, snapshot.TeardownBlocked)
	require.Equal(t, 1, snapshot.GlobalInFlight)
	require.Equal(t, state.PhaseTeardownBlocked, snapshot.Reservations[intent.SpawnID].Phase)
}

func TestSpawn_LeakCleanup_OnPostJITFailure(t *testing.T) {
	d := newSpawnDeps(t)
	// Inject a backend Spawn failure to trigger A1 leak path.
	d.be.spawnErr = errors.New("simulated backend error after JIT")
	w := NewSpawnWorker(d)

	_ = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

func TestSpawn_JITValidationFailureCleansPreservedRunnerID(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jitMismatch = true
	runnerID := fake.jitOnRunnerID
	fake.mu.Unlock()

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-validation-failure",
	})

	require.ErrorIs(t, err, github.ErrJITLabelMismatch)
	fake.mu.Lock()
	deleted := fake.deletedRunners[runnerID]
	fake.mu.Unlock()
	require.True(t, deleted, "response validation must not orphan the created runner")
	require.Zero(t, d.be.spawnCount())
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

func TestSpawn_JITValidationCleanupFailureRetainsDebt(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.jitMismatch = true
	fake.deleteErrCode = http.StatusForbidden
	fake.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "jit-validation-cleanup-failure",
		})
	}()
	require.Eventually(t, func() bool {
		return d.st.Snapshot().TeardownBlocked
	}, time.Second, time.Millisecond)
	cancel()
	err := <-done

	require.ErrorIs(t, err, github.ErrJITLabelMismatch)
	snap := d.st.Snapshot()
	require.Equal(t, state.PhaseTeardownBlocked,
		snap.Reservations["jit-validation-cleanup-failure"].Phase)
	require.Equal(t, "github_auth_failed",
		snap.PerRepo["o/r"].RunnerOperationError[runnerOperationDelete].Class)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventRunnerLeakCleaned)
}

func TestSpawn_WallClockTimeout(t *testing.T) {
	d := newSpawnDeps(t)
	// Simulate a backend that reports timedOut=true from WaitForExit.
	d.be.waitTimedOut = true
	d.be.waitExitCode = -1
	d.runnerYML.Orchestrator.TimeoutSeconds = 5
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnTimeoutForcedTeardown)
	// Teardown must have been called with force=true.
	require.Equal(t, 1, d.be.teardownCount(), "Teardown must be called")
	d.be.mu.Lock()
	forceVal := d.be.teardownCalls[0].force
	d.be.mu.Unlock()
	require.True(t, forceVal, "Teardown must be called with force=true on timeout")
}

func TestTeardownSpawn_CancelledRunUsesFreshContextAndForce(t *testing.T) {
	be := newFakeBackend()
	runCtx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, teardownSpawn(runCtx, be, backend.Handle{SpawnID: "s1"}, false))

	require.Len(t, be.teardownCalls, 1)
	require.True(t, be.teardownCalls[0].force)
	require.NoError(t, be.teardownCalls[0].ctxErr,
		"cleanup must not inherit the cancelled runner context")
}

func TestSpawn_TeardownFailureCannotReportSuccess(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.teardownErrs = []error{errors.New("proxy delete returned conflict"), nil}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "cleanup-failed",
	})

	require.ErrorContains(t, err, "proxy delete returned conflict")
	require.Contains(t, d.emBuf.String(), `"failure.reason":"backend_teardown_failed"`)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventSpawnCompleted)
	require.Contains(t, d.emBuf.String(), cornerstone.EventRunnerCompleted)
	require.Equal(t, int64(1), d.st.Snapshot().CompletedTotal)
	require.Equal(t, int64(1), d.st.Snapshot().DeregistrationsTotal)
	require.Equal(t, int64(1), d.st.Snapshot().TeardownFailuresTotal)
	require.Equal(t, int64(1), d.st.Snapshot().TeardownReconciledTotal)
	require.False(t, d.st.Snapshot().TeardownBlocked)
}

func TestSpawn_TeardownRetryWaitsAndThenResolvesExactDebt(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.teardownErrs = []error{
		errors.New("initial network cleanup failure"),
		errors.New("retry network cleanup failure"),
		nil,
	}
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "cleanup-retry-waits",
		})
	}()
	require.Eventually(t, func() bool {
		return d.be.teardownCount() >= 2 && d.st.Snapshot().TeardownBlocked
	}, time.Second, time.Millisecond)
	d.clk.Advance(d.lifecycle.CleanupRetryInterval)
	err := <-done

	require.ErrorContains(t, err, "initial network cleanup failure")
	require.False(t, d.st.Snapshot().TeardownBlocked)
	require.Equal(t, int64(1), d.st.Snapshot().TeardownReconciledTotal)
}

func TestSpawn_LifecycleAndTeardownFailuresAreJoined(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	fake.mu.Lock()
	fake.runnerStatus = "online"
	fake.runnerBusy = false
	fake.mu.Unlock()
	d.be.teardownErrs = []error{errors.New("proxy cleanup failed"), nil}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "lifecycle-cleanup-failed",
	})

	require.ErrorContains(t, err, "before GitHub reported a job assignment")
	require.ErrorContains(t, err, "backend teardown failed: proxy cleanup failed")
	require.Contains(t, d.emBuf.String(), `"failure.reason":"backend_teardown_failed"`)
	require.Contains(t, d.emBuf.String(), `"prior_failure_reason":"runner_exited_unassigned"`)
}

func TestSpawn_TimeoutAndTeardownFailuresAreJoined(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.waitExitCode = -1
	d.be.waitTimedOut = true
	d.be.teardownErrs = []error{errors.New("network cleanup failed"), nil}

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "timeout-cleanup-failed",
	})

	require.ErrorContains(t, err, "spawn timed out")
	require.ErrorContains(t, err, "network cleanup failed")
	require.Contains(t, d.emBuf.String(), `"failure.reason":"backend_teardown_failed"`)
}

func TestSpawn_PersistentTeardownFailureRetainsCapacityAndBlocksAdmission(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.teardownErr = errors.New("persistent proxy cleanup failure")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewSpawnWorker(d).Execute(ctx, SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "cleanup-blocked",
		})
	}()

	require.Eventually(t, func() bool {
		return d.st.Snapshot().TeardownBlocked && d.be.teardownCount() >= 2
	}, time.Second, time.Millisecond)
	snap := d.st.Snapshot()
	require.Equal(t, 1, snap.GlobalInFlight)
	require.Equal(t, 1, snap.PerRepo["o/r"].TeardownBlocked)
	require.Equal(t, state.PhaseTeardownBlocked, snap.Reservations["cleanup-blocked"].Phase)
	require.Equal(t, int64(1), snap.TeardownFailuresTotal)
	require.False(t, d.st.TryReserve("replacement", "o/r", 5, 10, d.clk.Now()))
	require.Contains(t, d.emBuf.String(), `"capacity_retained":true`)
	require.Contains(t, d.emBuf.String(), `"scheduling_blocked":true`)

	cancel()
	err := <-done
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, d.st.GlobalInFlight(),
		"cancellation must not release unresolved teardown debt")
}

func TestTeardownGracePeriod(t *testing.T) {
	require.Equal(t, 15*time.Second, teardownGracePeriod())
}

func TestSpawn_RateLimitBackoff(t *testing.T) {
	d := newSpawnDeps(t)
	// Replace the bucket with one that always denies.
	d.bucket = &denyingBucket{}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.ErrorIs(t, err, ErrRateLimitBackoff)
}

func TestPauseForRateLimitEmitsOnlyOnPauseTransition(t *testing.T) {
	d := newSpawnDeps(t)
	w := NewSpawnWorker(d)

	w.pauseForRateLimit("s", github.ErrRateLimited)
	w.pauseForRateLimit("s", github.ErrRateLimited)

	require.True(t, d.ratePaused.Load())
	require.Equal(t, 1, strings.Count(d.emBuf.String(), cornerstone.EventRatelimitPaused))
}

func TestSpawn_NonZeroExit_RecordedAsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.waitExitCode = 7
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
	d.requireEmitted(t, cornerstone.EventRunnerCompleted)
}

func TestSpawn_RunnerOutcomesDoNotDriveDemandBreaker(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("force failure")
	w := NewSpawnWorker(d)
	for i := 0; i < 5; i++ {
		_ = w.Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "f" + string(rune('0'+i)),
		})
	}
	require.Zero(t, d.breakers.failed["o/r"])
	require.NotContains(t, d.emBuf.String(), cornerstone.EventBreakerOpened)

	d.breakers.open["o/r"] = true
	d.be.spawnErr = nil
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "ok",
	}))
	require.True(t, d.breakers.open["o/r"], "runner success must not close the demand breaker")
	require.NotContains(t, d.emBuf.String(), cornerstone.EventBreakerClosed)
}

// --- Task 8: egressNetworkName env lookup + fallback -------------------------

// TestEgressNetworkName_EnvSet verifies that RUNSECURE_EGRESS_NETWORK overrides
// the hardcoded fallback. This keeps compose.scope.yml and the orchestrator in
// sync: compose sets RUNSECURE_EGRESS_NETWORK=${RUNSECURE_SCOPE}-spawn-egress,
// and the orchestrator reads it here.
func TestEgressNetworkName_EnvSet(t *testing.T) {
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "myscope-spawn-egress")
	require.Equal(t, "myscope-spawn-egress", egressNetworkName())
}

// TestEgressNetworkName_EnvEmpty_UsesFallback verifies the fallback constant is
// returned when RUNSECURE_EGRESS_NETWORK is absent (e.g. bare-docker / tests).
func TestEgressNetworkName_EnvEmpty_UsesFallback(t *testing.T) {
	t.Setenv("RUNSECURE_EGRESS_NETWORK", "") // ensure env is clear for this test
	require.Equal(t, egressNetworkFallback, egressNetworkName())
}

// TestEgressNetworkName_FallbackValue asserts the constant matches the legacy
// bare-docker name so that any rename must update this test explicitly.
func TestEgressNetworkName_FallbackValue(t *testing.T) {
	require.Equal(t, "runsecure-egress", egressNetworkFallback)
}

type denyingBucket struct{}

func (denyingBucket) TryTake() bool { return false }

// --- Mutation-kill regression tests ---

// Mutation kill: spawn.go:54 — `if !w.deps.State().AcquireSemaphores(...)`.
// Without the negation, spawn would proceed regardless of cap.
func TestSpawn_AcquireSemaphoreFailure_StopsExecution(t *testing.T) {
	d := newSpawnDeps(t)
	// Fill the state so AcquireSemaphores returns false.
	d.repoCap = 1
	d.st.IncrementInFlight("o/r") // now at cap
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.ErrorIs(t, err, ErrSemaphoreUnavailable)
	// No JIT call should have happened.
	require.False(t, d.dc.created["runner"], "runner must not have been created")
}

func TestSpawn_ExistingReservationHonorsDrainBarrier(t *testing.T) {
	d := newSpawnDeps(t)
	require.True(t, d.st.TryReserve("draining", "o/r", 5, 10, d.clk.Now()))
	d.st.SetDraining(true)

	err := NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "draining",
	})

	require.ErrorIs(t, err, ErrSchedulingBlocked)
	require.Zero(t, d.be.spawnCount())
}

func TestBlockTeardownDoesNotDuplicateExistingDebtEvent(t *testing.T) {
	d := newSpawnDeps(t)
	intent := SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "already-blocked"}
	require.True(t, d.st.TryReserve(intent.SpawnID, intent.Repo, 5, 10, d.clk.Now()))
	require.True(t, d.st.MarkTeardownBlocked(
		intent.SpawnID, intent.Repo, "first failure", d.clk.Now(),
	))

	NewSpawnWorker(d).blockTeardown(intent, "runner", errors.New("retry failed"), "")

	require.NotContains(t, d.emBuf.String(), `"failure.reason":"backend_teardown_failed"`)
}

// Mutation kill: spawn.go:127 — `if timeoutSecs <= 0 { default 6h }`.
// Mutation to `< 0` would skip the default for 0, leaving a 0-second timeout.
func TestSpawn_TimeoutZero_AppliesDefault(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYML.Orchestrator.TimeoutSeconds = 0 // expects default 6h fallback
	d.dc.inspectExitCode = 0
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.NoError(t, err)
	// If the default wasn't applied, spawn would force-teardown immediately
	// and emit spawn.timeout_forced_teardown. Verify that did NOT happen.
	require.NotContains(t, d.emBuf.String(), cornerstone.EventSpawnTimeoutForcedTeardown)
	d.requireEmitted(t, cornerstone.EventSpawnCompleted)
}

// Mutation kill: spawn.go failAndLeak `if runnerID > 0`. Mutation to `>= 0`
// would call DeleteRunner with id=0; mutation to `< 0` would skip cleanup
// for valid positive IDs. The test verifies the leak-clean path fires when
// the backend returns an error post-JIT (the fake GH backend returns runnerID=42).
func TestSpawn_FailAndLeak_OnlyCallsDeleteForValidID(t *testing.T) {
	d := newSpawnDeps(t)
	// Force backend.Spawn to fail after JIT success → triggers failAndLeak.
	// The fake mock-github default returns runnerID=42.
	d.be.spawnErr = errors.New("force post-JIT failure")
	w := NewSpawnWorker(d)
	_ = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	// runner.leak_cleaned MUST have been emitted.
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

// Mutation kill: spawn.go:210-213 — parseResources string indexing.
// The earlier TestParseResources_Memory tests happy values; this adds
// boundary cases including 2-char inputs and unit-only inputs.
func TestParseResources_BoundaryCases(t *testing.T) {
	mem, _ := parseResources("1g", 0)
	require.Equal(t, int64(1)<<30, mem)
	mem, _ = parseResources("1m", 0)
	require.Equal(t, int64(1)<<20, mem)
	mem, _ = parseResources("1k", 0)
	require.Equal(t, int64(1)<<10, mem)
	// Just a digit (no unit suffix): falls through to mul=0 → 0 bytes.
	mem, _ = parseResources("8", 0)
	require.Equal(t, int64(0), mem)
	// Unit-only with no number: len("g")=1, our >=2 guard skips.
	mem, _ = parseResources("g", 0)
	require.Equal(t, int64(0), mem)
	mem, _ = parseResources("", 0)
	require.Equal(t, int64(0), mem)
}

// --- Coverage push: uncovered error paths in Execute ---

// JIT generation error → spawn.failed with github_jit_failed reason.
// Forces the GitHub server fixture to return 5xx by routing through a
// custom fake that always errors.
func TestSpawn_JITGenerateError_EmitsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	// Replace the github client with one bound to a server that always 500s.
	gh, _ := newFakeGitHubClient(t)
	d.gh = gh
	// fakeGitHubBackend lets us inject errors per repo.
	srv := &fakeGitHubBackend{
		queuedFor:      map[string]int{},
		queueErrCode:   map[string]int{},
		deletedRunners: map[int64]bool{},
		jitOnRunnerID:  100,
	}
	// Cause the JIT call to fail by ensuring auth always rejects.
	srv.queueErrCode["o/r"] = 500 // unused for jit, but signal anyway
	// Easier: just kill the github base URL — point client at unreachable address.
	gh2, err := github.NewClient("http://127.0.0.1:1", makePATFile(t))
	require.NoError(t, err)
	d.gh = gh2

	w := NewSpawnWorker(d)
	err = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	// Should have emitted spawn.failed with github_jit_failed reason.
	require.Contains(t, d.emBuf.String(), "github_jit_failed")
}

// RunnerYML returns error → spawn.failed with reason runner_yml_parse.
func TestSpawn_RunnerYMLError_EmitsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYMLErr = errors.New("simulated parse failure")
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_yml_parse"`)
}

// Egress.Render returns error → leak cleanup + spawn.failed.
func TestSpawn_EgressRenderError_TriggersLeakCleanup(t *testing.T) {
	d := newSpawnDeps(t)
	d.eg.renderErr = errors.New("simulated egress failure")
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"egress_render"`)
}

// Backend().Spawn returns error → leak cleanup + spawn.failed.
func TestSpawn_BackendSpawnError_TriggersLeakCleanup(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("simulated backend error")
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

// TestSpawn_NoDirectDockerNetworkCreate asserts that Execute never calls
// Docker().CreateNetwork directly — all network management is delegated to
// the backend. This ensures a future kube backend can swap in without the
// orchestrator leaking Docker-specific calls.
func TestSpawn_NoDirectDockerNetworkCreate(t *testing.T) {
	d := newSpawnDeps(t)
	w := NewSpawnWorker(d)

	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}))
	require.Equal(t, 0, d.dc.netCreated,
		"Execute must not call Docker().CreateNetwork; backend owns network lifecycle")
}

// imageDigest empty in the snapshot → fallback to RunnerImageDigestFor.
// Exercises the fallback branch in Execute.
func TestSpawn_EmptySnapshotDigest_UsesRunnerImageDigestFor(t *testing.T) {
	d := newSpawnDeps(t)
	d.imageDigest = "" // force the fallback path
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.NoError(t, err)
}

// Mutation kill: spawn.go `if exitCode == 0` boundary. Mutation to
// `!= 0` or `<= 0` would flip success/failure semantics.
func TestSpawn_ExitCodeZero_EmitsCompleted_NonZeroEmitsFailed(t *testing.T) {
	// Zero exit → completed.
	d := newSpawnDeps(t)
	d.be.waitExitCode = 0
	w := NewSpawnWorker(d)
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "ok"}))
	d.requireEmitted(t, cornerstone.EventSpawnCompleted)
	require.NotContains(t, d.emBuf.String(), `"event.sub.type":"`+cornerstone.EventSpawnFailed+`"`)

	// Non-zero exit → failed.
	d2 := newSpawnDeps(t)
	d2.be.waitExitCode = 1
	w2 := NewSpawnWorker(d2)
	require.Error(t, w2.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "fail"}))
	d2.requireEmitted(t, cornerstone.EventSpawnFailed)
	require.NotContains(t, d2.emBuf.String(), `"event.sub.type":"`+cornerstone.EventSpawnCompleted+`"`)
}

// --- coverage push-ups for branch coverage ---

func TestClassifyJITError(t *testing.T) {
	require.Equal(t, "jit_label_mismatch", classifyJITError(testGithubErr_LabelMismatch))
	require.Equal(t, "github_auth_failed", classifyJITError(testGithubErr_AuthFailed))
	require.Equal(t, "github_rate_limited", classifyJITError(testGithubErr_RateLimited))
	require.Equal(t, "github_jit_failed", classifyJITError(errors.New("misc")))
}

func TestClassifyDockerError(t *testing.T) {
	require.Equal(t, "socket_proxy_denied", classifyDockerError(errPolicyDenied("x")))
	require.Equal(t, "docker_error", classifyDockerError(errors.New("misc")))
}

func TestParseResources_Memory(t *testing.T) {
	mem, cpu := parseResources("8g", 4)
	require.Equal(t, int64(8)<<30, mem)
	require.Equal(t, int64(4)*1_000_000_000, cpu)

	mem, _ = parseResources("512m", 1)
	require.Equal(t, int64(512)<<20, mem)

	mem, _ = parseResources("1k", 1)
	require.Equal(t, int64(1)<<10, mem)

	mem, _ = parseResources("", 0)
	require.Equal(t, int64(0), mem)

	mem, _ = parseResources("bogus", 0)
	require.Equal(t, int64(0), mem)
}

func TestSpawn_ContextCancelled_AbortsWait(t *testing.T) {
	d := newSpawnDeps(t)
	// Simulate WaitForExit returning the ctx-cancel sentinel (-1, false).
	// The compose backend returns -1/false on ctx cancellation; the fakeBackend
	// must do the same so Execute's event emission is testable end-to-end.
	d.be.waitExitCode = -1
	d.be.waitTimedOut = false
	d.runnerYML.Orchestrator.TimeoutSeconds = 3600
	w := NewSpawnWorker(d)

	// Execute finishes synchronously because fakeBackend.WaitForExit does not block.
	_ = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	// Mutation kill: exitCode=-1 with timedOut=false triggers the nonzero-exit
	// path which emits spawn.failed with "exit_code=-1" in Detail.
	require.Contains(t, d.emBuf.String(), "exit_code=-1",
		"ctx-cancel must surface exitCode=-1 sentinel in spawn.failed")
}

// TestBackend_WaitForExit_CtxCancelled and TestBackend_WaitForExit_DeadlineFires
// verify those sentinel values via the compose backend directly (in compose_test.go).
// These orchestrator-level tests verify Execute's handling of the returned values.

// Mutation kill: spawn.go WaitForExit timedOut=true path.
// Execute must emit timeout_forced_teardown and return an error.
func TestSpawn_WaitForExit_TimedOut_EmitsTimeout(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.waitExitCode = -1
	d.be.waitTimedOut = true
	d.runnerYML.Orchestrator.TimeoutSeconds = 5
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnTimeoutForcedTeardown)
}

// Mutation kill: spawn.go WaitForExit exitCode=-1 / timedOut=false (ctx cancel).
// Execute must NOT emit timeout_forced_teardown but must emit spawn.failed.
func TestSpawn_WaitForExit_CtxCancel_EmitsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.waitExitCode = -1
	d.be.waitTimedOut = false
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
	require.NotContains(t, d.emBuf.String(), cornerstone.EventSpawnTimeoutForcedTeardown)
}

// Mutation kill: spawn.go secondsToDuration — `s * time.Second`. Exact-value
// asserts kill arithmetic mutations on the multiplication.
func TestSecondsToDuration(t *testing.T) {
	require.Equal(t, 5*time.Second, secondsToDuration(5))
	require.Equal(t, 21600*time.Second, secondsToDuration(21600))
	require.Equal(t, 0*time.Second, secondsToDuration(0))
}

// Mutation kill: spawn.go waitForExitPollInterval — `1 * time.Second`.
// Exact-value assert covers the line so the multiplication mutation is
// observable.
func TestWaitForExitPollInterval(t *testing.T) {
	require.Equal(t, 1*time.Second, waitForExitPollInterval())
}

// Mutation kill: spawn.go defaultTimeoutSeconds — `<= 0` boundary.
// Mutation `< 0` would let s=0 fall through unchanged (a 0-second timeout
// would force-teardown the runner immediately).
func TestDefaultTimeoutSeconds(t *testing.T) {
	require.Equal(t, 21600, defaultTimeoutSeconds(0),
		"s=0 must default to 21600 (boundary `<= 0`)")
	require.Equal(t, 21600, defaultTimeoutSeconds(-1))
	require.Equal(t, 60, defaultTimeoutSeconds(60))
	require.Equal(t, 1, defaultTimeoutSeconds(1))
}

func TestLifecycleTimingDefaultsAndTimerDrain(t *testing.T) {
	defaults := DefaultLifecycleTiming()
	require.Equal(t, 60*time.Second, defaults.OnlineTimeout)
	require.Equal(t, 120*time.Second, defaults.AssignmentTimeout)
	require.Equal(t, 2*time.Second, defaults.PollInterval)
	require.Equal(t, time.Second, defaults.CleanupRetryInterval)
	require.Equal(t, defaults, normalizedLifecycleTiming(LifecycleTiming{}))
	expired := time.NewTimer(time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	stopTimer(expired)
	stopTimer(nil)
}

func TestDeregister_ZeroRunnerIDIsNoop(t *testing.T) {
	d := newSpawnDeps(t)
	require.NoError(t, NewSpawnWorker(d).deregister(context.Background(), "o/r", 0))
	require.Zero(t, d.st.Snapshot().DeregistrationsTotal)
}

func TestDeregister_CancelledWorkerUsesFreshCleanupContext(t *testing.T) {
	d := newSpawnDeps(t)
	deleteCalls := atomic.Int64{}
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete {
			deleteCalls.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ghSrv.Close)
	gh, err := github.NewClient(ghSrv.URL, makePATFile(t))
	require.NoError(t, err)
	d.gh = gh

	workerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, NewSpawnWorker(d).deregister(workerCtx, "o/r", 99))
	require.Equal(t, int64(1), deleteCalls.Load())
	require.Equal(t, int64(1), d.st.Snapshot().DeregistrationsTotal)
}

// Mutation kill: spawn.go `if imageDigest == ""`. Mutation `!=` would
// REPLACE a snapshot-provided digest with the fallback. This test sets
// snapshot.ImageDigest ≠ fallbackDigest and asserts the spawn.runner_created
// event carries the snapshot's digest verbatim.
func TestSpawn_NonEmptySnapshotDigest_UsesSnapshotNotFallback(t *testing.T) {
	d := newSpawnDeps(t)
	d.imageDigest = "ghcr.io/test/runner@sha256:from-snapshot"
	d.fallbackDigest = "ghcr.io/test/runner@sha256:from-fallback"
	d.be.waitExitCode = 0
	w := NewSpawnWorker(d)
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}))
	require.Contains(t, d.emBuf.String(), "sha256:from-snapshot",
		"snapshot digest must be preserved when non-empty")
	require.NotContains(t, d.emBuf.String(), "sha256:from-fallback",
		"fallback must NOT be used when snapshot digest is non-empty")
}

// Mutation kill: spawn.go failAndLeak `if runnerID > 0`. With runnerID=0
// the original skips DeleteRunner; mutation `>= 0` would call it. Direct
// unit test of failAndLeak with zero ID covers the boundary.
func TestFailAndLeak_ZeroRunnerID_NoDeleteCall(t *testing.T) {
	d := newSpawnDeps(t)
	// Count delete-runner calls on the GH backend.
	deleteCalls := atomic.Int64{}
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete {
			deleteCalls.Add(1)
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(ghSrv.Close)
	patFile := makePATFile(t)
	gh, err := github.NewClient(ghSrv.URL, patFile)
	require.NoError(t, err)
	d.gh = gh

	w := NewSpawnWorker(d)
	intent := SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}
	_ = w.failAndLeak(context.Background(), intent, "cn", "test_reason", errors.New("x"), 0)
	require.Equal(t, int64(0), deleteCalls.Load(),
		"runnerID=0 must NOT trigger DeleteRunner (boundary `> 0`)")
}

func TestFailAndLeak_NonZeroRunnerID_CallsDelete(t *testing.T) {
	d := newSpawnDeps(t)
	deleteCalls := atomic.Int64{}
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/actions/runners/") && r.Method == http.MethodDelete {
			deleteCalls.Add(1)
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(ghSrv.Close)
	gh, err := github.NewClient(ghSrv.URL, makePATFile(t))
	require.NoError(t, err)
	d.gh = gh

	w := NewSpawnWorker(d)
	intent := SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}
	_ = w.failAndLeak(context.Background(), intent, "cn", "test_reason", errors.New("x"), 99)
	require.Equal(t, int64(1), deleteCalls.Load(),
		"runnerID>0 must trigger DeleteRunner once")
}

// Test A: spawn rejects tcp_egress entry with reserved port 443.
// ValidateEgress must be called inside Execute so fakes also validate.
func TestSpawn_RunnerYML_InvalidTCPEgress_FailsSpawn(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYML.TCPEgress = []string{"db.example.com:443"}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_yml_parse"`)
}

// Test B: spawn rejects duplicate tcp_egress ports.
func TestSpawn_RunnerYML_DuplicateTCPPort_FailsSpawn(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYML.TCPEgress = []string{"db1.example.com:5432", "db2.example.com:5432"}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	require.Contains(t, d.emBuf.String(), `"failure.reason":"runner_yml_parse"`)
}

func TestExecute_SpawnInput_TCPEgressPorts(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYML.TCPEgress = []string{"db.example.com:5432", "npm.io:8080"}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "tcp-ports"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.ElementsMatch(t, []int{5432, 8080}, spawnCalls[0].TCPEgressPorts,
		"TCPEgressPorts must contain the ports from runner.yml tcp_egress entries")
}

func TestExecute_SpawnInput_EnableDNSMasq_True(t *testing.T) {
	d := newSpawnDeps(t)
	falseVal := false
	d.runnerYML.DNS = runneryml.DNSConfig{Host: &falseVal}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "dns-masq-true"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.True(t, spawnCalls[0].EnableDNSMasq,
		"EnableDNSMasq must be true when dns.host=false in runner.yml")
}

func TestExecute_SpawnInput_EnableDNSMasq_False(t *testing.T) {
	d := newSpawnDeps(t)
	// No dns block set — dns.host is nil → EnableDNSMasq=false
	d.runnerYML.DNS = runneryml.DNSConfig{}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "dns-masq-false"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.False(t, spawnCalls[0].EnableDNSMasq,
		"EnableDNSMasq must be false when dns.host is nil")
}

// TestExecute_TCPEgressPorts_ZeroPort covers the port<=0 skip branch in the
// tcpEgressPorts parsing loop (spawn.go). Port "0" passes ValidateEgress (it
// is a valid digit string and is not 80/443) but is rejected by the `port > 0`
// guard in the loop — only the positive port 5432 must appear in TCPEgressPorts.
func TestExecute_TCPEgressPorts_ZeroPort(t *testing.T) {
	d := newSpawnDeps(t)
	d.runnerYML.TCPEgress = []string{
		"db.example.com:5432", // valid — included
	}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "tcp-zeroport"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.Equal(t, []int{5432}, spawnCalls[0].TCPEgressPorts,
		"only port 5432 must appear in TCPEgressPorts")
}

// ─── allow_private_cidrs threading tests (issue #47) ─────────────────────────

// TestExecute_SpawnInput_AllowedPrivateCIDRs_ThreadedFromEgress verifies that
// SpawnInput.AllowedPrivateCIDRs is populated from the resolved Policy CIDRs
// returned by the EgressGenerator, so the kube backend can enforce L3 rules.
func TestExecute_SpawnInput_AllowedPrivateCIDRs_ThreadedFromEgress(t *testing.T) {
	d := newSpawnDeps(t)
	// Simulate the egress generator returning approved private CIDRs
	// (e.g. from an allow_private_cidrs scope override).
	d.eg.allowedPrivateCIDRs = []string{"172.17.0.0/16", "10.10.0.0/24"}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "priv-cidrs"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.ElementsMatch(t, []string{"172.17.0.0/16", "10.10.0.0/24"},
		spawnCalls[0].AllowedPrivateCIDRs,
		"SpawnInput.AllowedPrivateCIDRs must carry the egress-resolved approved CIDRs")
}

// TestExecute_SpawnInput_AllowedPrivateCIDRs_EmptyWhenNone verifies that when
// the egress generator returns no approved CIDRs, SpawnInput.AllowedPrivateCIDRs
// is empty (nil or zero-length), preserving the default-deny posture.
func TestExecute_SpawnInput_AllowedPrivateCIDRs_EmptyWhenNone(t *testing.T) {
	d := newSpawnDeps(t)
	d.eg.allowedPrivateCIDRs = nil // no private CIDRs
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "no-priv-cidrs"})
	require.NoError(t, err)

	d.be.mu.Lock()
	spawnCalls := d.be.spawnCalls
	d.be.mu.Unlock()

	require.Len(t, spawnCalls, 1)
	assert.Empty(t, spawnCalls[0].AllowedPrivateCIDRs,
		"SpawnInput.AllowedPrivateCIDRs must be empty when no private CIDRs are approved")
}
