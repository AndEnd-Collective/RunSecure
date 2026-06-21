package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// contentsResponse is the relevant subset of GitHub's Contents API response.
// The full schema has many fields; we only need content + encoding.
type contentsResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// GetRunnerYML fetches .github/runner.yml from the given repo via the GitHub
// Contents API. It supports conditional requests via the If-None-Match header:
//
//   - If etag is non-empty, the header is sent and a 304 response causes
//     GetRunnerYML to return (nil, "", true, nil) — callers must reuse
//     their cached snapshot.
//   - On a 200 response the decoded YAML bytes and the new ETag are returned.
//   - Any non-200/304 status is returned as an error.
//
// The returned body is the raw YAML bytes (base64-decoded from the GitHub
// API response). The newETag value is empty when the server did not send one.
func (c *Client) GetRunnerYML(ctx context.Context, repo, etag string) (body []byte, newETag string, notModified bool, err error) {
	path := fmt.Sprintf("/repos/%s/contents/.github/runner.yml", repo)

	tok, err := c.provider.Token(ctx)
	if err != nil {
		return nil, "", false, fmt.Errorf("github: get token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, "", false, err
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: %w", repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, "", true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: unexpected status %d", repo, resp.StatusCode)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: read body: %w", repo, err)
	}

	var cr contentsResponse
	if err := json.Unmarshal(rawBody, &cr); err != nil {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: decode JSON: %w", repo, err)
	}
	if cr.Encoding != "base64" {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: unexpected encoding %q (want base64)", repo, cr.Encoding)
	}

	// GitHub base64-encodes with newlines; strip them before decoding.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
	if err != nil {
		return nil, "", false, fmt.Errorf("github: get runner.yml for %s: base64 decode: %w", repo, err)
	}

	newETag = resp.Header.Get("ETag")
	return decoded, newETag, false, nil
}
