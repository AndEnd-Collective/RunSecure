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
	"time"
)

var (
	ErrAuthFailed                   = errors.New("github: authentication failed (401/403)")
	ErrRateLimited                  = errors.New("github: rate-limited")
	ErrRunnerNotFound               = errors.New("github: runner not found")
	ErrRecentJobSearchIndeterminate = errors.New("github: recent workflow job search exhausted its safety bound")
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
	Conclusion string   `json:"conclusion"`
	Labels     []string `json:"labels"`
	RunnerID   int64    `json:"runner_id"`
	RunnerName string   `json:"runner_name"`
}

// RecentJobSearchBounds bounds the fallback used to correlate a short-lived
// JIT runner after it has disappeared from the runner API. Since is sent to
// GitHub's workflow-runs created filter. PriorityRunIDs are searched without
// that filter so a later dependent job in an already-existing candidate run
// cannot be missed. MaxRuns and MaxAPICalls are separate fail-closed guards:
// reaching either before every eligible page is consumed makes the result
// indeterminate rather than evidence of an unassigned exit.
type RecentJobSearchBounds struct {
	Since          time.Time
	PriorityRunIDs []int64
	MaxRuns        int
	MaxAPICalls    int
}

// RecentJobSearchResult carries both the match and the last observed rate
// limit so callers preserve the runner-management readiness signal.
type RecentJobSearchResult struct {
	Job          WorkflowJob
	Found        bool
	RateLimit    RateLimit
	RunsExamined int
	APICalls     int
}

// FindRecentWorkflowJobByRunner searches latest-attempt jobs from workflow
// runs that GitHub classifies as queued, in progress, or completed. It is a
// fallback for jobs that became eligible after the scheduler's demand poll.
// A clean no-match is returned only after every page inside the time bound was
// consumed; safety-bound exhaustion returns ErrRecentJobSearchIndeterminate.
func (c *Client) FindRecentWorkflowJobByRunner(
	ctx context.Context,
	repo string,
	runnerID int64,
	runnerName string,
	bounds RecentJobSearchBounds,
) (RecentJobSearchResult, error) {
	if bounds.Since.IsZero() {
		return RecentJobSearchResult{}, errors.New("github: recent job search requires a non-zero since time")
	}
	if bounds.MaxRuns <= 0 || bounds.MaxAPICalls <= 0 {
		return RecentJobSearchResult{}, errors.New("github: recent job search bounds must be positive")
	}
	if runnerID <= 0 && runnerName == "" {
		return RecentJobSearchResult{}, errors.New("github: recent job search requires a runner id or name")
	}

	search := recentJobSearcher{
		client: c, repo: repo, runnerID: runnerID, runnerName: runnerName,
		bounds: bounds,
	}
	return search.run(ctx)
}

type recentJobSearcher struct {
	client     *Client
	repo       string
	runnerID   int64
	runnerName string
	bounds     RecentJobSearchBounds
	result     RecentJobSearchResult
}

func (s *recentJobSearcher) run(ctx context.Context) (RecentJobSearchResult, error) {
	seenRuns := make(map[int64]bool, len(s.bounds.PriorityRunIDs))
	for _, runID := range s.bounds.PriorityRunIDs {
		if runID <= 0 || seenRuns[runID] {
			continue
		}
		seenRuns[runID] = true
		if s.result.RunsExamined >= s.bounds.MaxRuns {
			return s.result, s.boundError("workflow run limit")
		}
		s.result.RunsExamined++
		found, err := s.searchRun(ctx, runID)
		if err != nil {
			return s.result, err
		}
		if found {
			return s.result, nil
		}
	}

	for _, status := range []string{"queued", "in_progress", "completed"} {
		for page := 1; ; page++ {
			runs, err := s.workflowRunsPage(ctx, status, page)
			if err != nil {
				return s.result, err
			}
			for _, run := range runs {
				if seenRuns[run.ID] {
					continue
				}
				seenRuns[run.ID] = true
				if s.result.RunsExamined >= s.bounds.MaxRuns {
					return s.result, s.boundError("workflow run limit")
				}
				s.result.RunsExamined++
				found, err := s.searchRun(ctx, run.ID)
				if err != nil {
					return s.result, err
				}
				if found {
					return s.result, nil
				}
			}
			if len(runs) < githubPageSize {
				break
			}
		}
	}
	return s.result, nil
}

func (s *recentJobSearcher) workflowRunsPage(
	ctx context.Context,
	status string,
	page int,
) ([]WorkflowRun, error) {
	query := url.Values{}
	query.Set("status", status)
	query.Set("created", ">="+s.bounds.Since.UTC().Format(time.RFC3339))
	query.Set("per_page", fmt.Sprint(githubPageSize))
	query.Set("page", fmt.Sprint(page))
	path := fmt.Sprintf("/repos/%s/actions/runs?%s", s.repo, query.Encode())
	resp, err := s.do(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, responseError(resp, "list recent workflow runs")
	}
	var body workflowRunsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("github: decode recent workflow runs: %w", err)
	}
	return body.WorkflowRuns, nil
}

func (s *recentJobSearcher) searchRun(ctx context.Context, runID int64) (bool, error) {
	for page := 1; ; page++ {
		query := url.Values{}
		query.Set("filter", "latest")
		query.Set("per_page", fmt.Sprint(githubPageSize))
		query.Set("page", fmt.Sprint(page))
		path := fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?%s", s.repo, runID, query.Encode())
		resp, err := s.do(ctx, path)
		if err != nil {
			return false, err
		}
		if resp.StatusCode != http.StatusOK {
			err := responseError(resp, "list recent workflow jobs")
			_ = resp.Body.Close()
			return false, err
		}
		var body workflowJobsResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			return false, fmt.Errorf("github: decode recent workflow jobs: %w", err)
		}
		for _, job := range body.Jobs {
			if !workflowJobMatchesRunner(job, s.runnerID, s.runnerName) {
				continue
			}
			job.RunID = runID
			s.result.Job = job
			s.result.Found = true
			return true, nil
		}
		if len(body.Jobs) < githubPageSize {
			return false, nil
		}
	}
}

func (s *recentJobSearcher) do(ctx context.Context, path string) (*http.Response, error) {
	if s.result.APICalls >= s.bounds.MaxAPICalls {
		return nil, s.boundError("API call limit")
	}
	s.result.APICalls++
	resp, err := s.client.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	s.result.RateLimit = newestRateLimit(s.result.RateLimit, ParseRateLimit(resp.Header))
	return resp, nil
}

func (s *recentJobSearcher) boundError(bound string) error {
	return fmt.Errorf(
		"%w: %s reached after %d runs and %d API calls",
		ErrRecentJobSearchIndeterminate, bound, s.result.RunsExamined, s.result.APICalls,
	)
}

func workflowJobMatchesRunner(job WorkflowJob, runnerID int64, runnerName string) bool {
	if job.Status != "in_progress" && job.Status != "completed" {
		return false
	}
	if job.RunnerID > 0 && runnerID > 0 {
		return job.RunnerID == runnerID
	}
	return runnerName != "" && job.RunnerName == runnerName
}

// GetWorkflowJob returns the current state and runner correlation for one job.
// The scheduler carries candidate job IDs into a spawn so a fast JIT job that
// completes between runner samples can still prove assignment after exit.
func (c *Client) GetWorkflowJob(ctx context.Context, repo string, jobID int64) (WorkflowJob, RateLimit, error) {
	resp, err := c.Do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/jobs/%d", repo, jobID), nil)
	if err != nil {
		return WorkflowJob{}, RateLimit{}, err
	}
	defer resp.Body.Close()
	lim := ParseRateLimit(resp.Header)
	if resp.StatusCode != http.StatusOK {
		return WorkflowJob{}, lim, responseError(resp, "get workflow job")
	}
	var job WorkflowJob
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return WorkflowJob{}, lim, fmt.Errorf("github: decode workflow job: %w", err)
	}
	return job, lim, nil
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
