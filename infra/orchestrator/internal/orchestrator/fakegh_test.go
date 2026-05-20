package orchestrator

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/stretchr/testify/require"
)

// newFakeGitHubClient constructs a github.Client backed by a
// fakeGitHubBackend, returning both the client and the backend so tests
// can mutate the backend state mid-run.
func newFakeGitHubClient(t *testing.T) (*github.Client, *fakeGitHubBackend) {
	t.Helper()
	back := newFakeGH()
	srv := httptest.NewServer(back.handler())
	t.Cleanup(srv.Close)

	patDir := t.TempDir()
	patFile := filepath.Join(patDir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))

	gh, err := github.NewClient(srv.URL, patFile)
	require.NoError(t, err)
	return gh, back
}
