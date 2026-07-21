package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClient_AddsAuthorizationHeader(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_xxxx\n"), 0o400))

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, patFile)
	require.NoError(t, err)
	resp, err := c.Do(context.Background(), http.MethodGet, "/repos/o/r", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "Bearer ghp_xxxx", gotAuth)
}

func TestClient_RequestObserverReceivesResponseStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c := makeClient(t, srv.URL)
	var method, path, status string
	c.SetRequestObserver(func(gotMethod, gotPath, gotStatus string) {
		method, path, status = gotMethod, gotPath, gotStatus
	})

	resp, err := c.Do(context.Background(), http.MethodPost, "/repos/o/r/actions/runners/generate-jitconfig", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.MethodPost, method)
	require.Equal(t, "/repos/o/r/actions/runners/generate-jitconfig", path)
	require.Equal(t, "202", status)
}

func TestClient_RequestObserverReceivesTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	c := makeClient(t, srv.URL)
	var status string
	c.SetRequestObserver(func(_, _, gotStatus string) { status = gotStatus })

	_, err := c.Do(context.Background(), http.MethodGet, "/x", nil)
	require.Error(t, err)
	require.Equal(t, "transport_error", status)
}

func TestClient_ReloadsPATOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_v1\n"), 0o400))

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, patFile)
	require.NoError(t, err)

	resp, _ := c.Do(context.Background(), "GET", "/x", nil)
	resp.Body.Close()

	// Rewrite + force mtime change. 0400 files are read-only, so chmod
	// briefly to 0600 to allow the write, then back to 0400.
	require.NoError(t, os.Chmod(patFile, 0o600))
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_v2\n"), 0o600))
	require.NoError(t, os.Chmod(patFile, 0o400))
	future := time.Now().Add(time.Second)
	require.NoError(t, os.Chtimes(patFile, future, future))

	resp, _ = c.Do(context.Background(), "GET", "/x", nil)
	resp.Body.Close()

	require.Equal(t, []string{"Bearer ghp_v1", "Bearer ghp_v2"}, seen)
}

func TestClient_PostBodyMarshaled(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := readAll(r.Body)
		gotBody = b
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, patFile)
	require.NoError(t, err)
	resp, err := c.Do(context.Background(), "POST", "/x", map[string]string{"k": "v"})
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, string(gotBody), `"k":"v"`)
}

// Mutation kill: client.go HTTPClientTimeout — `30 * time.Second`.
// Asserting the exact value kills arithmetic mutations on the operands.
func TestHTTPClientTimeout(t *testing.T) {
	require.Equal(t, 30*time.Second, HTTPClientTimeout())
}

func TestClient_MissingPATFile_Errors(t *testing.T) {
	_, err := NewClient("http://x", "/nonexistent/pat")
	require.Error(t, err)
}

func TestClient_Do_UnmarshalableBody(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	c, err := NewClient("http://x", patFile)
	require.NoError(t, err)
	// channels are unmarshalable by encoding/json.
	_, err = c.Do(context.Background(), "POST", "/x", make(chan int))
	require.Error(t, err)
}

func TestClient_Do_BadURL(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	c, err := NewClient("http://[::1]:x", patFile) // invalid port
	require.NoError(t, err)
	_, err = c.Do(context.Background(), "GET", "/x", nil)
	require.Error(t, err)
}

// Mutation kill: client.go:101 — `if bodyReader != nil { Content-Type }`.
// Mutation `==` would set Content-Type on GET requests that have no body.
func TestClient_GET_NoContentType(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))

	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, patFile)
	require.NoError(t, err)
	resp, err := c.Do(context.Background(), http.MethodGet, "/x", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Empty(t, gotCT, "GET with nil body must not set Content-Type")
}

func TestClient_Reload_StatFails(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("p"), 0o400))
	c, err := NewClient("http://x", patFile)
	require.NoError(t, err)
	require.NoError(t, os.Remove(patFile))
	_, err = c.Do(context.Background(), "GET", "/x", nil)
	require.Error(t, err)
}

// TestClient_Reload_ReadFileFails covers the os.ReadFile error branch inside
// reload. After construction succeeds, we force a reload by bumping mtime, then
// strip read permission from the file so Stat succeeds but ReadFile fails.
func TestClient_Reload_ReadFileFails(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))

	c, err := NewClient("http://127.0.0.1:9999", patFile)
	require.NoError(t, err)

	// Make the file unreadable (Stat still works; only the directory x-bit matters).
	require.NoError(t, os.Chmod(patFile, 0o000))
	t.Cleanup(func() { _ = os.Chmod(patFile, 0o600) })

	// Force mtime change so maybeReload considers the PAT stale and calls reload.
	future := time.Now().Add(time.Second)
	require.NoError(t, os.Chtimes(patFile, future, future))

	_, err = c.Do(context.Background(), "GET", "/x", nil)
	require.Error(t, err, "Do must fail when reload cannot read the PAT file")
	require.Contains(t, err.Error(), "read pat")
}

// Tiny io reader without pulling in additional imports in this file's tests.
func readAll(r interface {
	Read(p []byte) (n int, err error)
	Close() error
}) ([]byte, error) {
	defer r.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 256)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, nil
		}
	}
}
