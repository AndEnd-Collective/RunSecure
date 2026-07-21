package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrJITLabelMismatch is the B3 sanity-check failure: the JIT response
// label set didn't include every label we requested.
var ErrJITLabelMismatch = errors.New("github: JIT response labels did not match requested labels (B3 sanity check)")

type JITConfigRequest struct {
	Name          string   `json:"name"`
	RunnerGroupID int      `json:"runner_group_id"`
	Labels        []string `json:"labels"`
	WorkFolder    string   `json:"work_folder"`
}

type JITConfigResponse struct {
	RunnerID         int64
	EncodedJITConfig string
}

// Runner is the lifecycle subset returned by GitHub's runner detail endpoint.
type Runner struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Busy   bool   `json:"busy"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// rawJITResponse mirrors GitHub's wire format closely enough for our needs.
type rawJITResponse struct {
	Runner struct {
		ID     int64 `json:"id"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	} `json:"runner"`
	EncodedJITConfig string `json:"encoded_jit_config"`
}

func (c *Client) GenerateJITConfig(ctx context.Context, repo string, req JITConfigRequest) (JITConfigResponse, error) {
	if req.RunnerGroupID == 0 {
		req.RunnerGroupID = 1
	}
	if req.WorkFolder == "" {
		req.WorkFolder = "_work"
	}
	resp, err := c.Do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/actions/runners/generate-jitconfig", repo), req)
	if err != nil {
		return JITConfigResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnprocessableEntity {
		return JITConfigResponse{}, responseError(resp, "generate JIT config")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return JITConfigResponse{}, responseError(resp, "generate JIT config")
	}

	var raw rawJITResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		// json.Decoder can populate fields that precede malformed trailing
		// content. Preserve any runner identity GitHub already created so the
		// caller can deregister it instead of leaking an orphan registration.
		return jitConfigResponse(raw), fmt.Errorf("github: decode jit response: %w", err)
	}
	result := jitConfigResponse(raw)

	// B3 sanity check: if the response carries labels, they must include
	// each label we requested. If the labels field is empty, GitHub didn't
	// echo them and we cannot check — proceed.
	if len(raw.Runner.Labels) > 0 {
		gotLabels := make(map[string]bool, len(raw.Runner.Labels))
		for _, l := range raw.Runner.Labels {
			gotLabels[l.Name] = true
		}
		for _, want := range req.Labels {
			if !gotLabels[want] {
				return result, fmt.Errorf("%w: requested %q, response missing it", ErrJITLabelMismatch, want)
			}
		}
	}

	return result, nil
}

func jitConfigResponse(raw rawJITResponse) JITConfigResponse {
	return JITConfigResponse{
		RunnerID:         raw.Runner.ID,
		EncodedJITConfig: raw.EncodedJITConfig,
	}
}

// DeleteRunner removes a runner registration from GitHub. Used by A1 leak
// cleanup when a spawn fails after JIT generation but before the runner
// container starts (or claims a job).
func (c *Client) DeleteRunner(ctx context.Context, repo string, runnerID int64) error {
	resp, err := c.Do(ctx, http.MethodDelete,
		fmt.Sprintf("/repos/%s/actions/runners/%d", repo, runnerID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotFound:
		return nil // 404 = already gone, fine
	default:
		return responseError(resp, "delete runner")
	}
}

type runnersResponse struct {
	Runners []Runner `json:"runners"`
}

// ListRunners returns every repository runner registration. Cold-start
// reconciliation uses the exact runner names recorded on recovered containers
// to deregister only RunSecure-owned JIT runners before removing containers.
func (c *Client) ListRunners(ctx context.Context, repo string) ([]Runner, RateLimit, error) {
	all := make([]Runner, 0)
	lim := RateLimit{}
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/actions/runners?per_page=%d&page=%d", repo, githubPageSize, page)
		resp, err := c.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, lim, err
		}
		pageLimit := ParseRateLimit(resp.Header)
		lim = newestRateLimit(lim, pageLimit)
		if resp.StatusCode != http.StatusOK {
			err := responseError(resp, "list runners")
			_ = resp.Body.Close()
			return nil, lim, err
		}
		var body runnersResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, lim, fmt.Errorf("github: decode runners: %w", err)
		}
		all = append(all, body.Runners...)
		if len(body.Runners) < githubPageSize {
			return all, lim, nil
		}
	}
}

// GetRunner returns the current GitHub lifecycle state for a JIT runner.
func (c *Client) GetRunner(ctx context.Context, repo string, runnerID int64) (Runner, RateLimit, error) {
	resp, err := c.Do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/runners/%d", repo, runnerID), nil)
	if err != nil {
		return Runner{}, RateLimit{}, err
	}
	defer resp.Body.Close()
	lim := ParseRateLimit(resp.Header)
	if resp.StatusCode != http.StatusOK {
		return Runner{}, lim, responseError(resp, "get runner")
	}
	var runner Runner
	if err := json.NewDecoder(resp.Body).Decode(&runner); err != nil {
		return Runner{}, lim, fmt.Errorf("github: decode runner: %w", err)
	}
	return runner, lim, nil
}
