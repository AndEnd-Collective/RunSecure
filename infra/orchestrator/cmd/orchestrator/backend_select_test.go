package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/docker"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/github"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/state"
	"github.com/stretchr/testify/require"
)

// --- selectBackend ---

// fakeBackend is a minimal backend.Backend for testing selectBackend.
type fakeBackend struct{ name string }

func (f *fakeBackend) Name() string { return f.name }
func (f *fakeBackend) Spawn(_ context.Context, _ backend.SpawnInput) (backend.Handle, error) {
	return backend.Handle{}, nil
}
func (f *fakeBackend) WaitForExit(_ context.Context, _ backend.Handle, _ time.Duration) (int, bool) {
	return 0, false
}
func (f *fakeBackend) Teardown(_ context.Context, _ backend.Handle, _ bool) error { return nil }
func (f *fakeBackend) Reconcile(_ context.Context, _ string) ([]backend.Handle, error) {
	return nil, nil
}

// TestSelectBackend_Kube_ReturnsKubeBackend verifies that when scope.Backend=="kube"
// selectBackend calls the kubeCtor and returns its result.
func TestSelectBackend_Kube_ReturnsKubeBackend(t *testing.T) {
	kb := &fakeBackend{name: "kube"}
	kubeCtor := func() (backend.Backend, error) { return kb, nil }

	s := &config.Scope{Backend: "kube"}
	got, err := selectBackend(s, nil, kubeCtor)
	require.NoError(t, err)
	require.Equal(t, "kube", got.Name())
}

// TestSelectBackend_Kube_PropagatesCtorError verifies that an error from kubeCtor
// is propagated to the caller.
func TestSelectBackend_Kube_PropagatesCtorError(t *testing.T) {
	kubeCtor := func() (backend.Backend, error) {
		return nil, errors.New("no in-cluster config")
	}

	s := &config.Scope{Backend: "kube"}
	_, err := selectBackend(s, nil, kubeCtor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no in-cluster config")
}

// TestSelectBackend_Compose_ReturnsComposeBackend verifies that when
// scope.Backend=="compose" selectBackend returns a compose backend (kubeCtor
// is never called).
func TestSelectBackend_Compose_ReturnsComposeBackend(t *testing.T) {
	called := false
	kubeCtor := func() (backend.Backend, error) {
		called = true
		return nil, errors.New("should not be called")
	}

	dc, _ := docker.NewClient("tcp://127.0.0.1:9999")
	s := &config.Scope{Backend: "compose"}
	got, err := selectBackend(s, dc, kubeCtor)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.False(t, called, "kubeCtor must not be called for compose backend")
	require.Equal(t, "compose", got.Name())
}

// TestSelectBackend_Empty_DefaultsToCompose verifies the defensive empty-string arm.
// config.Validate normalises "" to "compose" before selectBackend is called, but
// selectBackend must not panic or call kubeCtor if "" somehow reaches it.
func TestSelectBackend_Empty_DefaultsToCompose(t *testing.T) {
	called := false
	kubeCtor := func() (backend.Backend, error) {
		called = true
		return nil, errors.New("should not be called")
	}

	dc, _ := docker.NewClient("tcp://127.0.0.1:9999")
	s := &config.Scope{Backend: ""}
	got, err := selectBackend(s, dc, kubeCtor)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.False(t, called)
	require.Equal(t, "compose", got.Name())
}

// --- loadRunnerYMLFromAPI ---

// makeGHClient returns a GitHub client pointed at the given test server URL.
func makeGHClient(t *testing.T, serverURL string) *github.Client {
	t.Helper()
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))
	c, err := github.NewClient(serverURL, patFile)
	require.NoError(t, err)
	return c
}

// contentsResp mirrors the GitHub Contents API wire format (subset used by GetRunnerYML).
type contentsResp struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// TestLoadRunnerYMLFromAPI_200_ReturnsParsedSnapshot verifies the happy path:
// a 200 response returns a parsed RunnerYMLSnapshot and stores the new ETag.
func TestLoadRunnerYMLFromAPI_200_ReturnsParsedSnapshot(t *testing.T) {
	yamlContent := "runtime: node:24\nhttp_egress:\n  - api.github.com\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag-v1"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	snap, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.NotNil(t, snap.YML)
	require.Equal(t, "node:24", snap.YML.Runtime)
	require.Equal(t, `"etag-v1"`, st.LastETag("o/r"),
		"ETag must be stored in state after a 200 response")
}

// TestLoadRunnerYMLFromAPI_304_ReturnsNotModifiedSentinel verifies that a 304
// response returns errRunnerYMLNotModified so callers can reuse a cached snapshot.
func TestLoadRunnerYMLFromAPI_304_ReturnsNotModifiedSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()
	st.SetLastETag("o/r", `"cached"`)

	_, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.ErrorIs(t, err, errRunnerYMLNotModified,
		"304 must return the errRunnerYMLNotModified sentinel")
}

// TestLoadRunnerYMLFromAPI_APIError_PropagatesError verifies that a non-200/304
// status is surfaced as an error.
func TestLoadRunnerYMLFromAPI_APIError_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	_, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.Error(t, err)
	require.NotErrorIs(t, err, errRunnerYMLNotModified)
}

// TestLoadRunnerYMLFromAPI_InvalidYAML_Error verifies that a malformed YAML
// body from the API returns an error (not a panic or silent empty snapshot).
func TestLoadRunnerYMLFromAPI_InvalidYAML_Error(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(": : : not yaml"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	_, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.Error(t, err)
}

// TestLoadRunnerYMLFromAPI_EgressValidationFails_Error verifies that a runner.yml
// with invalid egress (e.g. duplicate TCP port) returns an error, not a
// snapshot with an invalid config.
func TestLoadRunnerYMLFromAPI_EgressValidationFails_Error(t *testing.T) {
	// Two entries for the same port — ValidateEgress must reject this.
	yamlContent := "runtime: node:24\ntcp_egress:\n  - db.example.com:5432\n  - other.example.com:5432\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	_, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.Error(t, err)
	require.Contains(t, err.Error(), "egress")
}

// TestLoadRunnerYMLFromAPI_NoETag_StateUnchanged verifies that when the API
// response has no ETag header, the state is not written (no empty ETag stored).
func TestLoadRunnerYMLFromAPI_NoETag_StateUnchanged(t *testing.T) {
	yamlContent := "runtime: node:24\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately omit ETag header.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	snap, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.Empty(t, st.LastETag("o/r"),
		"no ETag in response must not write an empty ETag to state")
}

// TestLoadRunnerYMLFromAPI_DeprecationWarning_DoesNotFail verifies that a
// runner.yml using the deprecated egress.allow_domains key still returns a
// valid snapshot (the warning is advisory, not a fatal error).
func TestLoadRunnerYMLFromAPI_DeprecationWarning_DoesNotFail(t *testing.T) {
	yamlContent := "runtime: node:24\negress:\n  allow_domains:\n    - api.github.com\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	snap, err := loadRunnerYMLFromAPI(context.Background(), gh, st, "o/r")
	require.NoError(t, err, "deprecated field must emit warning, not error")
	require.NotNil(t, snap)
}

// --- productionDeps.RunnerYML kube path ---

// TestRunnerYML_KubeBackend_FetchesFromAPI verifies that when Backend=="kube"
// the RunnerYML method fetches via the GitHub API instead of from disk.
func TestRunnerYML_KubeBackend_FetchesFromAPI(t *testing.T) {
	yamlContent := "runtime: node:24\nhttp_egress:\n  - api.github.com\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResp{Content: encoded, Encoding: "base64"})
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()

	pd := &productionDeps{
		gh: gh,
		st: st,
		scopeRef: &config.Scope{
			Backend: "kube",
			Repos:   []config.RepoBlock{{Repo: "o/r"}},
		},
	}

	snap, err := pd.RunnerYML("o/r")
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.Equal(t, "node:24", snap.YML.Runtime,
		"kube backend must return the runner.yml fetched from the GitHub API")
}

// TestRunnerYML_KubeBackend_304_ReturnsNotModifiedSentinel verifies that a
// 304 response from the GitHub API causes RunnerYML to return errRunnerYMLNotModified.
func TestRunnerYML_KubeBackend_304_ReturnsNotModifiedSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	gh := makeGHClient(t, srv.URL)
	st := state.New()
	st.SetLastETag("o/r", `"cached"`)

	pd := &productionDeps{
		gh: gh,
		st: st,
		scopeRef: &config.Scope{
			Backend: "kube",
			Repos:   []config.RepoBlock{{Repo: "o/r"}},
		},
	}

	_, err := pd.RunnerYML("o/r")
	require.ErrorIs(t, err, errRunnerYMLNotModified)
}

// TestRunnerYML_KubeBackend_UnknownRepo_Error verifies that an unknown repo
// returns an "unknown repo" error even in kube mode.
func TestRunnerYML_KubeBackend_UnknownRepo_Error(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Backend: "kube",
			Repos:   []config.RepoBlock{{Repo: "o/r"}},
		},
	}
	_, err := pd.RunnerYML("o/other")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown repo")
}

// --- productionDeps.RunnerYML compose error paths ---

// TestRunnerYML_ComposeBackend_ParseError verifies that a missing runner.yml
// on disk returns an error from the compose path.
func TestRunnerYML_ComposeBackend_ParseError(t *testing.T) {
	pd := &productionDeps{
		scopeRef: &config.Scope{
			Backend: "compose",
			Repos:   []config.RepoBlock{{Repo: "o/r", ProjectDir: "/nonexistent/dir"}},
		},
	}
	_, err := pd.RunnerYML("o/r")
	require.Error(t, err, "missing runner.yml must return an error in compose mode")
}

// TestRunnerYML_ComposeBackend_EgressValidationError verifies that an invalid
// runner.yml (bad egress) returns an egress validation error.
func TestRunnerYML_ComposeBackend_EgressValidationError(t *testing.T) {
	dir := t.TempDir()
	ghDir := filepath.Join(dir, ".github")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	// Duplicate TCP port — should fail egress validation.
	require.NoError(t, os.WriteFile(filepath.Join(ghDir, "runner.yml"), []byte(`
runtime: node:24
tcp_egress:
  - db.example.com:5432
  - other.example.com:5432
`), 0o644))

	pd := &productionDeps{
		scopeRef: &config.Scope{
			Backend: "compose",
			Repos:   []config.RepoBlock{{Repo: "o/r", ProjectDir: dir}},
		},
	}

	_, err := pd.RunnerYML("o/r")
	require.Error(t, err)
	require.Contains(t, err.Error(), "egress")
}
