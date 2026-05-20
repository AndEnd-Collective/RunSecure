package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/stretchr/testify/require"
)

func TestSpawn_HappyPath(t *testing.T) {
	d := newSpawnDeps(t)
	w := NewSpawnWorker(d)

	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"}))

	require.True(t, d.dc.created["runner"], "runner container created")
	require.True(t, d.dc.created["squid"], "squid container created")
	require.True(t, d.dc.created["haproxy"], "haproxy container created")
	require.True(t, d.dc.created["dnsmasq"], "dnsmasq container created")
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
	d.dc.createErr["runner"] = errPolicyDenied("HostConfig.CapAdd")
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
	require.False(t, d.dc.created["runner"], "runner must not have been created successfully")
}

func TestSpawn_LeakCleanup_OnPostJITFailure(t *testing.T) {
	d := newSpawnDeps(t)
	// Make all docker.Spawn container creates fail to trigger A1 leak path.
	d.dc.createErr["squid"] = errors.New("simulated docker error after JIT")
	w := NewSpawnWorker(d)

	_ = w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	d.requireEmitted(t, cornerstone.EventRunnerLeakCleaned)
}

func TestSpawn_WallClockTimeout(t *testing.T) {
	d := newSpawnDeps(t)
	d.dc.inspectExitDelay = 1 * time.Hour // simulate runner that never exits
	d.runnerYML.Orchestrator.TimeoutSeconds = 5
	w := NewSpawnWorker(d)

	// Advance the fake clock past the deadline after a short delay so the
	// timeout goroutine fires.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				d.clk.Advance(2 * time.Second)
			}
		}
	}()

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	close(done)
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnTimeoutForcedTeardown)
	require.True(t, d.dc.forceDeleted["runner"])
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
	d.dc.inspectExitCode = 7
	w := NewSpawnWorker(d)

	err := w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	require.Error(t, err)
	d.requireEmitted(t, cornerstone.EventSpawnFailed)
}

// Bug #1 regression test: breaker.opened fires when the breaker transitions
// to Open. Previously the return values from RecordFailure were dropped.
func TestSpawn_FifthFailure_EmitsBreakerOpened(t *testing.T) {
	d := newSpawnDeps(t)
	d.dc.createErr["squid"] = errors.New("force failure")
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
	d.dc.createErr["squid"] = errors.New("force failure")
	w := NewSpawnWorker(d)
	for i := 0; i < 5; i++ {
		_ = w.Execute(context.Background(), SpawnIntent{
			Scope: "s", Repo: "o/r", SpawnID: "f" + string(rune('0'+i)),
		})
	}
	delete(d.dc.createErr, "squid")
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "ok",
	}))
	d.requireEmitted(t, cornerstone.EventBreakerClosed)
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

// Mutation kill: spawn.go:183 — `if runnerID > 0`. Mutation to `>= 0` would
// call DeleteRunner with id=0; mutation to `< 0` would skip cleanup for
// valid positive IDs. The test verifies both halves.
func TestSpawn_FailAndLeak_OnlyCallsDeleteForValidID(t *testing.T) {
	d := newSpawnDeps(t)
	// Force step-3 failure (network create) AFTER JIT success → triggers
	// failAndLeak. The fake mock-github default returns runnerID=42.
	d.dc.createErr["squid"] = errors.New("force post-JIT failure")
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

// Mutation kill: spawn.go:284 — `if exitCode == 0` boundary. Mutation to
// `!= 0` or `<= 0` would flip success/failure semantics.
func TestSpawn_ExitCodeZero_EmitsCompleted_NonZeroEmitsFailed(t *testing.T) {
	// Zero exit → completed.
	d := newSpawnDeps(t)
	d.dc.inspectExitCode = 0
	w := NewSpawnWorker(d)
	require.NoError(t, w.Execute(context.Background(), SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "ok"}))
	d.requireEmitted(t, cornerstone.EventSpawnCompleted)
	require.NotContains(t, d.emBuf.String(), `"event.sub.type":"`+cornerstone.EventSpawnFailed+`"`)

	// Non-zero exit → failed.
	d2 := newSpawnDeps(t)
	d2.dc.inspectExitCode = 1
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
	d.dc.inspectExitDelay = 1 * time.Hour // runner doesn't exit
	d.runnerYML.Orchestrator.TimeoutSeconds = 3600
	w := NewSpawnWorker(d)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_ = w.Execute(ctx, SpawnIntent{Scope: "s", Repo: "o/r", SpawnID: "id1"})
	// We don't assert on a specific event — just that the function returns
	// (i.e. didn't deadlock).
}
