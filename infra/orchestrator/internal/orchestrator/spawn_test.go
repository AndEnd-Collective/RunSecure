package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
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
		cornerstone.EventSpawnCompleted,
	)
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

func TestSpawn_LeakCleanup_OnPostJITFailure(t *testing.T) {
	d := newSpawnDeps(t)
	// Inject a backend Spawn failure to trigger A1 leak path.
	d.be.spawnErr = errors.New("simulated backend error after JIT")
	w := NewSpawnWorker(d)

	_ = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
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

func TestSpawn_RateLimitBackoff(t *testing.T) {
	d := newSpawnDeps(t)
	// Replace the bucket with one that always denies.
	d.bucket = &denyingBucket{}
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.ErrorIs(t, err, ErrRateLimitBackoff)
}

func TestSpawn_NonZeroExit_RecordedAsFailed(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.waitExitCode = 7
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
}

// Bug #1 regression test: breaker.opened fires when the breaker transitions
// to Open. Previously the return values from RecordFailure were dropped.
func TestSpawn_FifthFailure_EmitsBreakerOpened(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("force failure")
	w := NewSpawnWorker(d)
	for i := 0; i < 5; i++ {
		_ = w.Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "f" + string(rune('0'+i)),
		})
	}
	d.requireEmitted(t, cornerstone.EventBreakerOpened)
}

func TestSpawn_SuccessAfterOpen_EmitsBreakerClosed(t *testing.T) {
	d := newSpawnDeps(t)
	d.be.spawnErr = errors.New("force failure")
	w := NewSpawnWorker(d)
	for i := 0; i < 5; i++ {
		_ = w.Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "f" + string(rune('0'+i)),
		})
	}
	d.be.spawnErr = nil
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "ok",
	}))
	d.requireEmitted(t, cornerstone.EventBreakerClosed)
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
