package orchestrator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/server"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

type runtimeReadinessDeps struct {
	st  *state.State
	now time.Time
}

func (d runtimeReadinessDeps) StateSnapshot() state.Snapshot { return d.st.Snapshot() }
func (d runtimeReadinessDeps) PollIntervalSeconds() int      { return 10 }
func (d runtimeReadinessDeps) Now() time.Time                { return d.now }
func (d runtimeReadinessDeps) BackendReady(context.Context) error {
	return nil
}
func (d runtimeReadinessDeps) LastPollAt() time.Time { return d.now }

func TestRunnerManagementAuthFailureFailsReadinessButNotLiveness(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	d.st.Configure([]string{"o/r"}, 3, 3, "v2.1.8", "build")
	fake.mu.Lock()
	fake.jitErrCode = http.StatusForbidden
	fake.mu.Unlock()

	require.Error(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-auth-readiness",
	}))
	// A later read-only demand refresh succeeds, but cannot prove that the JIT
	// runner-management capability recovered.
	d.st.RecordPollSuccess("o/r", 1, d.clk.Now())
	deps := runtimeReadinessDeps{st: d.st, now: d.clk.Now()}

	readyResponse := httptest.NewRecorder()
	server.NewReadyz(deps).ServeHTTP(readyResponse,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, readyResponse.Code)
	require.Contains(t, readyResponse.Body.String(),
		"runner_operation_error:o/r:generate_jit_config:github_auth_failed")

	liveResponse := httptest.NewRecorder()
	emitter := cornerstone.NewEmitter(io.Discard,
		cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	server.NewHealthz(deps, emitter).ServeHTTP(liveResponse,
		httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, liveResponse.Code)
}

func TestRunnerManagementRateLimitFailsReadinessUntilSameOperationRecovers(t *testing.T) {
	d := newSpawnDeps(t)
	gh, fake := newFakeGitHubClient(t)
	d.gh = gh
	d.st.Configure([]string{"o/r"}, 3, 3, "v2.1.8", "build")
	fake.mu.Lock()
	fake.jitErrCode = http.StatusForbidden
	fake.rlAfterResponse = true
	fake.rlRemaining = 0
	fake.mu.Unlock()

	require.Error(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-rate-readiness",
	}))
	d.st.RecordPollSuccess("o/r", 1, d.clk.Now())
	deps := runtimeReadinessDeps{st: d.st, now: d.clk.Now()}

	readyResponse := httptest.NewRecorder()
	server.NewReadyz(deps).ServeHTTP(readyResponse,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, readyResponse.Code)
	require.Contains(t, readyResponse.Body.String(),
		"runner_operation_error:o/r:generate_jit_config:github_rate_limited")

	liveResponse := httptest.NewRecorder()
	emitter := cornerstone.NewEmitter(io.Discard,
		cornerstone.FixedClock("t"), cornerstone.FixedUUID("u"))
	server.NewHealthz(deps, emitter).ServeHTTP(liveResponse,
		httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, liveResponse.Code)

	// A successful demand refresh cannot clear the JIT capability failure;
	// only a successful call to that same runner-management operation can.
	fake.mu.Lock()
	fake.jitErrCode = 0
	fake.rlAfterResponse = false
	fake.mu.Unlock()
	require.NoError(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
		Scope: "s", Repo: "o/r", SpawnID: "jit-rate-recovered",
	}))

	recoveredResponse := httptest.NewRecorder()
	server.NewReadyz(deps).ServeHTTP(recoveredResponse,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, recoveredResponse.Code)
}

func TestRunnerManagementRuntimeFailuresFailReadinessUntilSameOperationRecovers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*fakeGitHubBackend)
		clear     func(*fakeGitHubBackend)
		wantClass string
	}{
		{
			name: "jit capacity response",
			configure: func(fake *fakeGitHubBackend) {
				fake.jitErrCode = http.StatusUnprocessableEntity
			},
			clear:     func(fake *fakeGitHubBackend) { fake.jitErrCode = 0 },
			wantClass: "github_jit_unavailable",
		},
		{
			name: "jit response label mismatch",
			configure: func(fake *fakeGitHubBackend) {
				fake.jitMismatch = true
			},
			clear:     func(fake *fakeGitHubBackend) { fake.jitMismatch = false },
			wantClass: "github_jit_label_mismatch",
		},
		{
			name: "github server failure",
			configure: func(fake *fakeGitHubBackend) {
				fake.jitErrCode = http.StatusInternalServerError
			},
			clear:     func(fake *fakeGitHubBackend) { fake.jitErrCode = 0 },
			wantClass: "github_runner_operation_failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newSpawnDeps(t)
			gh, fake := newFakeGitHubClient(t)
			d.gh = gh
			d.st.Configure([]string{"o/r"}, 3, 3, "v2.1.8", "build")
			fake.mu.Lock()
			tc.configure(fake)
			fake.mu.Unlock()

			require.Error(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
				Scope: "s", Repo: "o/r", SpawnID: "jit-runtime-readiness",
			}))
			d.st.RecordPollSuccess("o/r", 1, d.clk.Now())
			deps := runtimeReadinessDeps{st: d.st, now: d.clk.Now()}
			failed := httptest.NewRecorder()
			server.NewReadyz(deps).ServeHTTP(failed,
				httptest.NewRequest(http.MethodGet, "/readyz", nil))
			require.Equal(t, http.StatusServiceUnavailable, failed.Code)
			require.Contains(t, failed.Body.String(),
				"runner_operation_error:o/r:generate_jit_config:"+tc.wantClass)

			fake.mu.Lock()
			tc.clear(fake)
			fake.mu.Unlock()
			require.NoError(t, NewSpawnWorker(d).Execute(context.Background(), SpawnIntent{
				Scope: "s", Repo: "o/r", SpawnID: "jit-runtime-recovered",
			}))

			recovered := httptest.NewRecorder()
			server.NewReadyz(deps).ServeHTTP(recovered,
				httptest.NewRequest(http.MethodGet, "/readyz", nil))
			require.Equal(t, http.StatusOK, recovered.Code)
		})
	}
}
