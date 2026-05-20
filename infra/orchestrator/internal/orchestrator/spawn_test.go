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

type denyingBucket struct{}

func (denyingBucket) TryTake() bool { return false }

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
