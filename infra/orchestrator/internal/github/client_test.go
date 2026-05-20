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
