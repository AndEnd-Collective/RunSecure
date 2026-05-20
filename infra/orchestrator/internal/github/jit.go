package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return JITConfigResponse{}, ErrAuthFailed
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return JITConfigResponse{}, errors.New("github: 422 no JIT slot available")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return JITConfigResponse{}, fmt.Errorf("github: generate-jitconfig: status %d", resp.StatusCode)
	}

	var raw rawJITResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return JITConfigResponse{}, fmt.Errorf("github: decode jit response: %w", err)
	}

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
				return JITConfigResponse{}, fmt.Errorf("%w: requested %q, response missing it", ErrJITLabelMismatch, want)
			}
		}
	}

	return JITConfigResponse{
		RunnerID:         raw.Runner.ID,
		EncodedJITConfig: raw.EncodedJITConfig,
	}, nil
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrAuthFailed
	default:
		return fmt.Errorf("github: delete runner %d: status %d", runnerID, resp.StatusCode)
	}
}
