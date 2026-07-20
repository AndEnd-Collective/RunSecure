package server

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

func readyDeps(t *testing.T) *fakeDeps {
	t.Helper()
	d := newDeps(t)
	d.snap.ConfigLoaded = true
	r := d.snap.PerRepo["o/r"]
	r.LastPollAt = d.now
	r.LastPollSuccess = d.now
	r.LastPollError = ""
	r.LastErrorDetail = ""
	d.snap.PerRepo["o/r"] = r
	return d
}

func TestReadyz_ReadyOnlyAfterSuccessfulFreshDemandAndBackend(t *testing.T) {
	d := readyDeps(t)
	rr := httpRec()
	NewReadyz(d).ServeHTTP(rr, httpReq(http.MethodGet, "/readyz"))
	require.Equal(t, http.StatusOK, rr.Code)
	require.JSONEq(t, `{"status":"ready","ready":true}`, rr.Body.String())
}

func TestReadyz_FailsForBackendDependency(t *testing.T) {
	d := readyDeps(t)
	d.backendErr = errors.New("docker socket unavailable")
	rr := httpRec()
	NewReadyz(d).ServeHTTP(rr, httpReq(http.MethodGet, "/readyz"))
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	require.Contains(t, rr.Body.String(), `"ready":false`)
	require.Contains(t, rr.Body.String(), "backend_unreachable")
}

func TestReadinessReasons_FailClosed(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	snap := state.Snapshot{
		Draining: true,
		PerRepo: map[string]state.RepoState{
			"never/polled": {},
			"stale/repo":   {LastPollSuccess: now.Add(-30 * time.Second)},
			"auth/repo": {
				LastPollSuccess: now, LastPollError: "github_auth_failed", BreakerOpen: true,
			},
		},
	}
	reasons := readinessReasons(snap, now, 10)
	require.ElementsMatch(t, []string{
		"config_not_loaded", "draining", "poll_never_succeeded:never/polled",
		"poll_stale:stale/repo", "poll_error:auth/repo:github_auth_failed",
		"breaker_open:auth/repo",
	}, reasons)
}
