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
	"time"

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

func TestGetWorkflowJob_PreservesRunnerCorrelation(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/o/r/actions/jobs/91", r.URL.Path)
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4998")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 91, "name": "ci/setup", "status": "completed", "conclusion": "success",
			"runner_id": 73, "runner_name": "rs-fast-runner",
		})
	})

	job, limit, err := c.GetWorkflowJob(context.Background(), "o/r", 91)

	require.NoError(t, err)
	require.Equal(t, int64(73), job.RunnerID)
	require.Equal(t, "rs-fast-runner", job.RunnerName)
	require.Equal(t, "success", job.Conclusion)
	require.Equal(t, 4998, limit.Remaining)
}

func TestGetWorkflowJob_ClassifiesAuthFailure(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, _, err := c.GetWorkflowJob(context.Background(), "o/r", 91)

	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestGetWorkflowJob_MalformedAndNetworkFailures(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	_, _, err := c.GetWorkflowJob(context.Background(), "o/r", 91)
	require.ErrorContains(t, err, "decode workflow job")

	c, err = NewClient("http://127.0.0.1:1", makePATForQueue(t))
	require.NoError(t, err)
	_, _, err = c.GetWorkflowJob(context.Background(), "o/r", 91)
	require.Error(t, err)
}

func TestFindRecentWorkflowJobByRunner_FindsLatestAttemptAcrossStatusesAndJobPages(t *testing.T) {
	since := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	seenStatuses := map[string]bool{}
	seenJobPages := map[string]bool{}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4975")
		if r.URL.Path == "/repos/o/r/actions/runs" {
			seenStatuses[r.URL.Query().Get("status")] = true
			require.Equal(t, ">="+since.Format(time.RFC3339), r.URL.Query().Get("created"))
			runs := []map[string]any{}
			if r.URL.Query().Get("status") == "completed" {
				runs = append(runs, map[string]any{"id": 77})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs/77/jobs" {
			require.Equal(t, "latest", r.URL.Query().Get("filter"))
			page := r.URL.Query().Get("page")
			seenJobPages[page] = true
			jobs := make([]map[string]any, 0)
			if page == "1" {
				for id := 1; id <= githubPageSize; id++ {
					jobs = append(jobs, map[string]any{
						"id": id, "status": "completed", "runner_id": id + 1000,
					})
				}
			} else {
				jobs = append(jobs, map[string]any{
					"id": 9001, "status": "completed", "conclusion": "success",
					"runner_id": 73, "runner_name": "old-display-name",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
			return
		}
		http.NotFound(w, r)
	})

	result, err := c.FindRecentWorkflowJobByRunner(
		context.Background(), "o/r", 73, "rs-fast-runner",
		RecentJobSearchBounds{Since: since, MaxRuns: 5, MaxAPICalls: 8},
	)

	require.NoError(t, err)
	require.True(t, result.Found)
	require.Equal(t, int64(9001), result.Job.ID)
	require.Equal(t, int64(77), result.Job.RunID)
	require.Equal(t, map[string]bool{"1": true, "2": true}, seenJobPages)
	require.Equal(t, map[string]bool{"queued": true, "in_progress": true, "completed": true}, seenStatuses)
	require.Equal(t, 4975, result.RateLimit.Remaining)
}

func TestFindRecentWorkflowJobByRunner_PriorityRunFindsLaterDependentJob(t *testing.T) {
	listedRuns := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/actions/runs/55/jobs" {
			require.Equal(t, "latest", r.URL.Query().Get("filter"))
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{
				{
					"id": 552, "name": "later-dependent", "status": "completed",
					"runner_id": 73, "runner_name": "rs-fast-runner",
				},
			}})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs" {
			listedRuns = true
		}
		http.NotFound(w, r)
	})

	result, err := c.FindRecentWorkflowJobByRunner(
		context.Background(), "o/r", 73, "rs-fast-runner",
		RecentJobSearchBounds{
			Since: time.Now().Add(-time.Hour), PriorityRunIDs: []int64{55, 55},
			MaxRuns: 2, MaxAPICalls: 2,
		},
	)

	require.NoError(t, err)
	require.True(t, result.Found)
	require.Equal(t, int64(552), result.Job.ID)
	require.Equal(t, int64(55), result.Job.RunID)
	require.Equal(t, 1, result.RunsExamined, "duplicate priority run ids must be scanned once")
	require.False(t, listedRuns, "a priority-run match must avoid the broader recent-run search")
}

func TestFindRecentWorkflowJobByRunner_DeduplicatesPriorityRunFromRecentStatuses(t *testing.T) {
	jobCalls := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/actions/runs/55/jobs" {
			jobCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs" {
			runs := []map[string]any{}
			if r.URL.Query().Get("status") == "queued" {
				runs = append(runs, map[string]any{"id": 55})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
			return
		}
		http.NotFound(w, r)
	})

	result, err := c.FindRecentWorkflowJobByRunner(
		context.Background(), "o/r", 73, "runner",
		RecentJobSearchBounds{
			Since: time.Now().Add(-time.Hour), PriorityRunIDs: []int64{0, 55, 55},
			MaxRuns: 1, MaxAPICalls: 4,
		},
	)

	require.NoError(t, err)
	require.False(t, result.Found)
	require.Equal(t, 1, result.RunsExamined)
	require.Equal(t, 1, jobCalls, "priority run must not be re-scanned from a status listing")
}

func TestFindRecentWorkflowJobByRunner_NameIsOnlyFallbackWhenRunnerIDMissing(t *testing.T) {
	tests := []struct {
		name        string
		jobRunnerID int64
		want        bool
	}{
		{name: "missing id uses exact name", jobRunnerID: 0, want: true},
		{name: "different id cannot be overridden by name", jobRunnerID: 99, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/actions/runs/55/jobs") {
					_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{
						"id": 1, "status": "completed", "runner_id": tt.jobRunnerID,
						"runner_name": "rs-fast-runner",
					}}})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{}})
			})
			result, err := c.FindRecentWorkflowJobByRunner(
				context.Background(), "o/r", 73, "rs-fast-runner",
				RecentJobSearchBounds{
					Since: time.Now().Add(-time.Hour), PriorityRunIDs: []int64{55},
					MaxRuns: 2, MaxAPICalls: 6,
				},
			)
			require.NoError(t, err)
			require.Equal(t, tt.want, result.Found)
		})
	}
}

func TestFindRecentWorkflowJobByRunner_ExhaustiveNoMatchIsDefinitive(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{}})
	})
	result, err := c.FindRecentWorkflowJobByRunner(
		context.Background(), "o/r", 73, "rs-fast-runner",
		RecentJobSearchBounds{
			Since: time.Now().Add(-time.Hour), MaxRuns: 1, MaxAPICalls: 3,
		},
	)
	require.NoError(t, err)
	require.False(t, result.Found)
	require.Equal(t, 3, result.APICalls)
}

func TestFindRecentWorkflowJobByRunner_BoundExhaustionIsIndeterminate(t *testing.T) {
	t.Run("run bound", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/o/r/actions/runs" {
				_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 1}, {"id": 2}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
		})
		result, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{
				Since: time.Now().Add(-time.Hour), MaxRuns: 1, MaxAPICalls: 8,
			},
		)
		require.ErrorIs(t, err, ErrRecentJobSearchIndeterminate)
		require.False(t, result.Found)
		require.Equal(t, 1, result.RunsExamined)
	})

	t.Run("API bound while job page may remain", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/actions/runs/1/jobs") {
				jobs := make([]map[string]any, githubPageSize)
				for i := range jobs {
					jobs[i] = map[string]any{"id": i + 1, "status": "completed", "runner_id": 99}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
				return
			}
			http.NotFound(w, r)
		})
		result, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{
				Since: time.Now().Add(-time.Hour), PriorityRunIDs: []int64{1},
				MaxRuns: 1, MaxAPICalls: 1,
			},
		)
		require.ErrorIs(t, err, ErrRecentJobSearchIndeterminate)
		require.Equal(t, 1, result.APICalls)
	})
}

func TestFindRecentWorkflowJobByRunner_ClassifiesHTTPFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		remaining string
		want      error
	}{
		{name: "auth", status: http.StatusUnauthorized, want: ErrAuthFailed},
		{name: "forbidden", status: http.StatusForbidden, remaining: "12", want: ErrAuthFailed},
		{name: "rate header", status: http.StatusForbidden, remaining: "0", want: ErrRateLimited},
		{name: "rate status", status: http.StatusTooManyRequests, want: ErrRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-RateLimit-Limit", "5000")
				w.Header().Set("X-RateLimit-Remaining", tt.remaining)
				w.WriteHeader(tt.status)
			})
			result, err := c.FindRecentWorkflowJobByRunner(
				context.Background(), "o/r", 73, "runner",
				RecentJobSearchBounds{
					Since: time.Now().Add(-time.Hour), MaxRuns: 1, MaxAPICalls: 3,
				},
			)
			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.status, ErrorStatus(err))
			if tt.remaining == "0" {
				require.Zero(t, result.RateLimit.Remaining)
				require.Equal(t, 5000, result.RateLimit.Limit)
			}
		})
	}
}

func TestFindRecentWorkflowJobByRunner_MalformedAndInvalidInputs(t *testing.T) {
	t.Run("malformed run response", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		_, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{Since: time.Now(), MaxRuns: 1, MaxAPICalls: 1},
		)
		require.ErrorContains(t, err, "decode recent workflow runs")
	})

	t.Run("malformed job response", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		_, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{
				Since: time.Now(), PriorityRunIDs: []int64{1}, MaxRuns: 1, MaxAPICalls: 1,
			},
		)
		require.ErrorContains(t, err, "decode recent workflow jobs")
	})

	t.Run("invalid bounds", func(t *testing.T) {
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
		_, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 0, "",
			RecentJobSearchBounds{},
		)
		require.ErrorContains(t, err, "non-zero since")

		_, err = c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{Since: time.Now()},
		)
		require.ErrorContains(t, err, "bounds must be positive")

		_, err = c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 0, "",
			RecentJobSearchBounds{Since: time.Now(), MaxRuns: 1, MaxAPICalls: 1},
		)
		require.ErrorContains(t, err, "runner id or name")
	})
}

func TestFindRecentWorkflowJobByRunner_PaginatesWorkflowRuns(t *testing.T) {
	runPages := map[string]bool{}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/actions/runs" {
			page := r.URL.Query().Get("page")
			runPages[page] = true
			runs := make([]map[string]any, 0)
			if page == "1" {
				for id := 1; id <= githubPageSize; id++ {
					runs = append(runs, map[string]any{"id": id})
				}
			} else {
				runs = append(runs, map[string]any{"id": 200})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs/200/jobs" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{
				"id": 2001, "status": "in_progress", "runner_id": 73,
			}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
	})

	result, err := c.FindRecentWorkflowJobByRunner(
		context.Background(), "o/r", 73, "runner",
		RecentJobSearchBounds{
			Since: time.Now().Add(-time.Hour), MaxRuns: 101, MaxAPICalls: 104,
		},
	)

	require.NoError(t, err)
	require.True(t, result.Found)
	require.Equal(t, int64(2001), result.Job.ID)
	require.Equal(t, map[string]bool{"1": true, "2": true}, runPages)
}

func TestFindRecentWorkflowJobByRunner_AdditionalFailClosedBranches(t *testing.T) {
	t.Run("priority run cap", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
		})
		_, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{
				Since: time.Now(), PriorityRunIDs: []int64{0, 1, 1, 2},
				MaxRuns: 1, MaxAPICalls: 4,
			},
		)
		require.ErrorIs(t, err, ErrRecentJobSearchIndeterminate)
	})

	t.Run("job endpoint status", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/o/r/actions/runs" {
				_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 1}}})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{Since: time.Now(), MaxRuns: 1, MaxAPICalls: 2},
		)
		require.Equal(t, http.StatusInternalServerError, ErrorStatus(err))
	})

	t.Run("queued matching job is not evidence", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/actions/runs/1/jobs") {
				_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{
					"id": 1, "status": "queued", "runner_id": 73,
				}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{}})
		})
		result, err := c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{
				Since: time.Now(), PriorityRunIDs: []int64{1}, MaxRuns: 2, MaxAPICalls: 4,
			},
		)
		require.NoError(t, err)
		require.False(t, result.Found)
	})

	t.Run("network error", func(t *testing.T) {
		c, err := NewClient("http://127.0.0.1:1", makePATForQueue(t))
		require.NoError(t, err)
		_, err = c.FindRecentWorkflowJobByRunner(
			context.Background(), "o/r", 73, "runner",
			RecentJobSearchBounds{Since: time.Now(), MaxRuns: 1, MaxAPICalls: 1},
		)
		require.Error(t, err)
	})
}

func makePATForQueue(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pat")
	require.NoError(t, os.WriteFile(path, []byte("p"), 0o400))
	return path
}
