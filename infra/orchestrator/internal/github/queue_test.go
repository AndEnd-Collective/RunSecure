package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestQueuedJobs_Counts(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/o/r/actions/runs", r.URL.Path)
		require.Equal(t, "queued", r.URL.Query().Get("status"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 3,
		})
	})

	n, err := c.QueuedJobs(context.Background(), "o/r")
	require.NoError(t, err)
	require.Equal(t, 3, n)
}

func TestQueuedJobs_AuthFailed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.QueuedJobs(context.Background(), "o/r")
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestQueuedJobs_RateLimitedFromHeader(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.QueuedJobs(context.Background(), "o/r")
	require.ErrorIs(t, err, ErrRateLimited)
}

func TestQueuedJobs_429RateLimited(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.QueuedJobs(context.Background(), "o/r")
	require.ErrorIs(t, err, ErrRateLimited)
}

func TestQueuedJobs_UnexpectedStatus(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.QueuedJobs(context.Background(), "o/r")
	require.Error(t, err)
}

func TestQueuedJobs_MalformedResponse(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	})
	_, err := c.QueuedJobs(context.Background(), "o/r")
	require.Error(t, err)
}

// Cover the Do() network-error branch (server closed or network down).
func TestQueuedJobs_NetworkErrorBubbles(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	c, err := NewClient("http://127.0.0.1:1", patFile)
	require.NoError(t, err)
	_, err = c.QueuedJobs(context.Background(), "o/r")
	require.Error(t, err)
}
