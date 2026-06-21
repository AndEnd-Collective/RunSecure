// Package github implements a thin HTTP client to the GitHub REST API.
// Authentication is delegated to an auth.Provider, which may be a PAT
// provider (with mtime-based hot-reload) or a GitHub App provider (with
// cached installation tokens). Callers obtain a client via NewClient (PAT,
// backward-compatible) or NewClientWithProvider (any Provider).
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/auth"
)

const DefaultBaseURL = "https://api.github.com"

// Client is a thin HTTP client for the GitHub REST API. It delegates
// credential management to an auth.Provider; every outbound request carries
// the token returned by provider.Token(ctx).
type Client struct {
	baseURL  string
	provider auth.Provider
	hc       *http.Client
}

// HTTPClientTimeout is the per-request timeout for outbound GitHub calls.
// Accessor func (not const) so mutation testing observes the multiplication
// operator inside a covered function body.
func HTTPClientTimeout() time.Duration { return 30 * time.Second }

// NewClient constructs a Client that authenticates with a PAT stored in
// patFile (mode 0400 enforced). Backward-compatible with existing callers.
func NewClient(baseURL, patFile string) (*Client, error) {
	p, err := auth.NewPATProvider(patFile)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	return NewClientWithProvider(baseURL, p)
}

// NewClientWithProvider constructs a Client that uses the given auth.Provider
// for all requests. p must be non-nil and safe for concurrent use.
func NewClientWithProvider(baseURL string, p auth.Provider) (*Client, error) {
	return &Client{
		baseURL:  baseURL,
		provider: p,
		hc: &http.Client{
			Timeout: HTTPClientTimeout(),
		},
	}, nil
}

// Do issues a request. The body argument (if non-nil) is JSON-marshaled.
// Caller is responsible for closing resp.Body.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	tok, err := c.provider.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: get token: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("github: marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.hc.Do(req)
}
