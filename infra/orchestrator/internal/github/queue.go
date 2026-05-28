package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var (
	ErrAuthFailed  = errors.New("github: authentication failed (401/403)")
	ErrRateLimited = errors.New("github: rate-limited")
)

type queuedRunsResponse struct {
	TotalCount int `json:"total_count"`
}

// QueuedJobs returns the number of workflow runs in "queued" status for repo.
//
// repo is "owner/name".
func (c *Client) QueuedJobs(ctx context.Context, repo string) (int, error) {
	resp, err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/actions/runs?status=queued", repo), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var q queuedRunsResponse
		if err := json.NewDecoder(resp.Body).Decode(&q); err != nil {
			return 0, fmt.Errorf("github: decode queued runs: %w", err)
		}
		return q.TotalCount, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return 0, ErrRateLimited
		}
		return 0, ErrAuthFailed
	case http.StatusTooManyRequests:
		return 0, ErrRateLimited
	default:
		return 0, fmt.Errorf("github: unexpected status %d", resp.StatusCode)
	}
}
