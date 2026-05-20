// Package github implements a thin HTTP client to the GitHub REST API,
// using a fine-grained PAT loaded from a file (mode 0400). The PAT is
// re-read from disk when its mtime changes — supports PAT rotation
// without orchestrator restart.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const DefaultBaseURL = "https://api.github.com"

type Client struct {
	baseURL string
	patFile string
	hc      *http.Client

	mu    sync.RWMutex
	pat   string
	mtime time.Time
}

func NewClient(baseURL, patFile string) (*Client, error) {
	c := &Client{
		baseURL: baseURL,
		patFile: patFile,
		hc: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// reload reads the PAT file.
func (c *Client) reload() error {
	info, err := os.Stat(c.patFile)
	if err != nil {
		return fmt.Errorf("github: stat pat: %w", err)
	}
	b, err := os.ReadFile(c.patFile)
	if err != nil {
		return fmt.Errorf("github: read pat: %w", err)
	}
	c.mu.Lock()
	c.pat = strings.TrimSpace(string(b))
	c.mtime = info.ModTime()
	c.mu.Unlock()
	return nil
}

// maybeReload re-reads the PAT file iff its mtime has changed.
func (c *Client) maybeReload() error {
	info, err := os.Stat(c.patFile)
	if err != nil {
		return err
	}
	c.mu.RLock()
	stale := !info.ModTime().Equal(c.mtime)
	c.mu.RUnlock()
	if stale {
		return c.reload()
	}
	return nil
}

// Do issues a request. The body argument (if non-nil) is JSON-marshaled.
// Caller is responsible for closing resp.Body.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if err := c.maybeReload(); err != nil {
		return nil, err
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
	c.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+c.pat)
	c.mu.RUnlock()
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.hc.Do(req)
}
