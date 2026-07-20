package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, patFile)
	require.NoError(t, err)
	return c, srv
}

func TestEligibleQueuedJobs_EnumeratesRunStatesAndMatchesAllLabels(t *testing.T) {
	seenStatuses := map[string]bool{}
	seenLatest := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4990")
		switch {
		case r.URL.Path == "/repos/o/r/actions/runs":
			status := r.URL.Query().Get("status")
			seenStatuses[status] = true
			runs := []map[string]any{{"id": 10}}
			if status == "in_progress" {
				runs = []map[string]any{{"id": 10}, {"id": 20}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/10/jobs"):
			seenLatest = r.URL.Query().Get("filter") == "latest"
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{
				{"id": 101, "name": "eligible", "status": "queued", "labels": []string{"self-hosted", "Linux", "runsecure"}},
				{"id": 102, "name": "wrong labels", "status": "queued", "labels": []string{"self-hosted", "Linux"}},
				{"id": 103, "name": "already running", "status": "in_progress", "labels": []string{"self-hosted", "Linux", "runsecure"}},
			}})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/20/jobs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{
				{"id": 201, "name": "eligible two", "status": "queued", "labels": []string{"runsecure", "Linux", "self-hosted", "extra"}},
			}})
		default:
			http.NotFound(w, r)
		}
	})

	demand, err := c.EligibleQueuedJobs(context.Background(), "o/r", []string{"self-hosted", "Linux", "runsecure"})
	require.NoError(t, err)
	require.Equal(t, 2, demand.Count())
	require.Equal(t, []int64{101, 201}, []int64{demand.Jobs[0].ID, demand.Jobs[1].ID})
	require.Equal(t, int64(10), demand.Jobs[0].RunID)
	require.Equal(t, int64(20), demand.Jobs[1].RunID)
	require.True(t, seenStatuses["queued"])
	require.True(t, seenStatuses["in_progress"])
	require.True(t, seenLatest)
	require.Equal(t, 4990, demand.RateLimit.Remaining)
}

func TestEligibleQueuedJobs_PaginatesRunsAndJobs(t *testing.T) {
	runPages := map[int]int{}
	jobPages := map[int]int{}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		switch {
		case r.URL.Path == "/repos/o/r/actions/runs" && r.URL.Query().Get("status") == "queued":
			runPages[page]++
			runs := make([]map[string]any, 0)
			if page == 1 {
				for id := 1; id <= githubPageSize; id++ {
					runs = append(runs, map[string]any{"id": id})
				}
			} else if page == 2 {
				runs = append(runs, map[string]any{"id": 101})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
		case r.URL.Path == "/repos/o/r/actions/runs" && r.URL.Query().Get("status") == "in_progress":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{}})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/101/jobs"):
			jobPages[page]++
			jobs := make([]map[string]any, 0)
			if page == 1 {
				for id := 1; id <= githubPageSize; id++ {
					jobs = append(jobs, map[string]any{"id": 1000 + id, "status": "completed", "labels": []string{"runsecure"}})
				}
			} else if page == 2 {
				jobs = append(jobs, map[string]any{"id": 9999, "status": "queued", "labels": []string{"runsecure"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
		case strings.Contains(r.URL.Path, "/jobs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
		default:
			http.NotFound(w, r)
		}
	})

	demand, err := c.EligibleQueuedJobs(context.Background(), "o/r", []string{"runsecure"})
	require.NoError(t, err)
	require.Equal(t, 1, demand.Count())
	require.Equal(t, int64(9999), demand.Jobs[0].ID)
	require.Equal(t, map[int]int{1: 1, 2: 1}, runPages)
	require.Equal(t, map[int]int{1: 1, 2: 1}, jobPages)
}

func TestEligibleQueuedJobs_HTTPFailuresAreClassified(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		remaining string
		want      error
	}{
		{name: "auth", status: http.StatusUnauthorized, want: ErrAuthFailed},
		{name: "forbidden", status: http.StatusForbidden, want: ErrAuthFailed},
		{name: "rate header", status: http.StatusForbidden, remaining: "0", want: ErrRateLimited},
		{name: "rate status", status: http.StatusTooManyRequests, want: ErrRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-RateLimit-Remaining", tt.remaining)
				w.WriteHeader(tt.status)
			})
			_, err := c.EligibleQueuedJobs(context.Background(), "o/r", nil)
			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.status, ErrorStatus(err))
		})
	}
}

func TestEligibleQueuedJobs_UnexpectedAndMalformedResponses(t *testing.T) {
	t.Run("unexpected status", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err := c.EligibleQueuedJobs(context.Background(), "o/r", nil)
		require.Error(t, err)
		require.Equal(t, http.StatusInternalServerError, ErrorStatus(err))
	})
	t.Run("malformed runs", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		_, err := c.EligibleQueuedJobs(context.Background(), "o/r", nil)
		require.ErrorContains(t, err, "decode workflow runs")
	})
	t.Run("malformed jobs", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/jobs") {
				_, _ = w.Write([]byte("not json"))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 1}}})
		})
		_, err := c.EligibleQueuedJobs(context.Background(), "o/r", nil)
		require.ErrorContains(t, err, "decode workflow jobs")
	})
}

func TestEligibleQueuedJobs_NetworkErrorBubbles(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	c, err := NewClient("http://127.0.0.1:1", patFile)
	require.NoError(t, err)
	_, err = c.EligibleQueuedJobs(context.Background(), "o/r", nil)
	require.Error(t, err)
}

func TestContainsAllLabelsAndNewestRateLimit(t *testing.T) {
	require.True(t, containsAllLabels([]string{"a", "b"}, nil))
	require.True(t, containsAllLabels([]string{"a", "b"}, []string{"b", "a"}))
	require.False(t, containsAllLabels([]string{"a"}, []string{"a", "b"}))
	current := RateLimit{Limit: 1, Remaining: 1}
	require.Equal(t, current, newestRateLimit(current, RateLimit{}))
	candidate := RateLimit{Limit: 2, Remaining: 0}
	require.Equal(t, candidate, newestRateLimit(current, candidate))
	require.Equal(t, "github: op: status 500: unexpected", (&APIError{Status: 500, Operation: "op", Err: fmt.Errorf("unexpected")}).Error())
	require.Zero(t, ErrorStatus(fmt.Errorf("plain")))
	require.Equal(t, RateLimit{}, ErrorRateLimit(fmt.Errorf("plain")))
	apiErr := &APIError{Status: 429, RateLimit: RateLimit{Limit: 10, Remaining: 0}, Operation: "op", Err: ErrRateLimited}
	require.Equal(t, apiErr.RateLimit, ErrorRateLimit(apiErr))
}

func TestListWorkflowJobs_UnexpectedStatusAndNetworkError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, _, err := c.listWorkflowJobs(context.Background(), "o/r", 1)
	require.Error(t, err)
	require.Equal(t, http.StatusInternalServerError, ErrorStatus(err))

	c, err = NewClient("http://127.0.0.1:1", makePATForQueue(t))
	require.NoError(t, err)
	_, _, err = c.listWorkflowJobs(context.Background(), "o/r", 1)
	require.Error(t, err)
}

func makePATForQueue(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pat")
	require.NoError(t, os.WriteFile(path, []byte("p"), 0o400))
	return path
}
