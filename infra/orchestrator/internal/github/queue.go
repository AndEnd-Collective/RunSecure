package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrAuthFailed     = errors.New("github: authentication failed (401/403)")
	ErrRateLimited    = errors.New("github: rate-limited")
	ErrRunnerNotFound = errors.New("github: runner not found")
)

const githubPageSize = 100

// APIError preserves the HTTP status and rate-limit headers while retaining a
// stable sentinel for errors.Is callers.
type APIError struct {
	Status    int
	RateLimit RateLimit
	Err       error
	Operation string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("github: %s: status %d: %v", e.Operation, e.Status, e.Err)
}

func (e *APIError) Unwrap() error { return e.Err }

// ErrorStatus returns the HTTP status carried by an APIError, or zero.
func ErrorStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// ErrorRateLimit returns rate-limit headers carried by an APIError.
func ErrorRateLimit(err error) RateLimit {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.RateLimit
	}
	return RateLimit{}
}

type workflowRunsResponse struct {
	WorkflowRuns []WorkflowRun `json:"workflow_runs"`
}

type workflowJobsResponse struct {
	Jobs []WorkflowJob `json:"jobs"`
}

// WorkflowRun is the subset of a GitHub Actions workflow run needed for job
// demand discovery.
type WorkflowRun struct {
	ID int64 `json:"id"`
}

// WorkflowJob is the subset of a GitHub Actions job used by the scheduler and
// operator correlation surfaces.
type WorkflowJob struct {
	ID         int64    `json:"id"`
	RunID      int64    `json:"run_id,omitempty"`
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Labels     []string `json:"labels"`
	RunnerID   int64    `json:"runner_id"`
	RunnerName string   `json:"runner_name"`
}

// JobDemand is an atomic view of eligible queued jobs from the latest poll.
type JobDemand struct {
	Jobs      []WorkflowJob
	RateLimit RateLimit
}

func (d JobDemand) Count() int { return len(d.Jobs) }

// EligibleQueuedJobs enumerates queued and in-progress workflow runs, then
// counts their latest-attempt queued jobs whose label set contains every
// required label. Both run and job endpoints are fully paginated.
func (c *Client) EligibleQueuedJobs(ctx context.Context, repo string, requiredLabels []string) (JobDemand, error) {
	seenRuns := map[int64]bool{}
	runs := make([]WorkflowRun, 0)
	demand := JobDemand{}
	for _, status := range []string{"queued", "in_progress"} {
		listed, lim, err := c.listWorkflowRuns(ctx, repo, status)
		if err != nil {
			return JobDemand{}, err
		}
		demand.RateLimit = newestRateLimit(demand.RateLimit, lim)
		for _, run := range listed {
			if seenRuns[run.ID] {
				continue
			}
			seenRuns[run.ID] = true
			runs = append(runs, run)
		}
	}

	seenJobs := map[int64]bool{}
	for _, run := range runs {
		jobs, lim, err := c.listWorkflowJobs(ctx, repo, run.ID)
		if err != nil {
			return JobDemand{}, err
		}
		demand.RateLimit = newestRateLimit(demand.RateLimit, lim)
		for _, job := range jobs {
			if job.Status != "queued" || seenJobs[job.ID] || !containsAllLabels(job.Labels, requiredLabels) {
				continue
			}
			seenJobs[job.ID] = true
			job.RunID = run.ID
			demand.Jobs = append(demand.Jobs, job)
		}
	}
	return demand, nil
}

func (c *Client) listWorkflowRuns(ctx context.Context, repo, status string) ([]WorkflowRun, RateLimit, error) {
	all := make([]WorkflowRun, 0)
	lim := RateLimit{}
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/actions/runs?status=%s&per_page=%d&page=%d",
			repo, url.QueryEscape(status), githubPageSize, page)
		resp, err := c.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, lim, err
		}
		pageLimit := ParseRateLimit(resp.Header)
		lim = newestRateLimit(lim, pageLimit)
		if resp.StatusCode != http.StatusOK {
			err := responseError(resp, "list workflow runs")
			_ = resp.Body.Close()
			return nil, lim, err
		}
		var body workflowRunsResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, lim, fmt.Errorf("github: decode workflow runs: %w", err)
		}
		all = append(all, body.WorkflowRuns...)
		if len(body.WorkflowRuns) < githubPageSize {
			return all, lim, nil
		}
	}
}

func (c *Client) listWorkflowJobs(ctx context.Context, repo string, runID int64) ([]WorkflowJob, RateLimit, error) {
	all := make([]WorkflowJob, 0)
	lim := RateLimit{}
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?filter=latest&per_page=%d&page=%d",
			repo, runID, githubPageSize, page)
		resp, err := c.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, lim, err
		}
		pageLimit := ParseRateLimit(resp.Header)
		lim = newestRateLimit(lim, pageLimit)
		if resp.StatusCode != http.StatusOK {
			err := responseError(resp, "list workflow jobs")
			_ = resp.Body.Close()
			return nil, lim, err
		}
		var body workflowJobsResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, lim, fmt.Errorf("github: decode workflow jobs: %w", err)
		}
		all = append(all, body.Jobs...)
		if len(body.Jobs) < githubPageSize {
			return all, lim, nil
		}
	}
}

func responseError(resp *http.Response, operation string) error {
	_, _ = io.Copy(io.Discard, resp.Body)
	lim := ParseRateLimit(resp.Header)
	sentinel := fmt.Errorf("unexpected response")
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		sentinel = ErrRateLimited
	case resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		sentinel = ErrRateLimited
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		sentinel = ErrAuthFailed
	case resp.StatusCode == http.StatusNotFound && strings.Contains(operation, "runner"):
		sentinel = ErrRunnerNotFound
	}
	return &APIError{Status: resp.StatusCode, RateLimit: lim, Err: sentinel, Operation: operation}
}

func containsAllLabels(got, required []string) bool {
	set := make(map[string]bool, len(got))
	for _, label := range got {
		set[label] = true
	}
	for _, label := range required {
		if !set[label] {
			return false
		}
	}
	return true
}

func newestRateLimit(current, candidate RateLimit) RateLimit {
	if candidate.Limit != 0 || candidate.Remaining != 0 || candidate.ResetUnix != 0 {
		return candidate
	}
	return current
}
