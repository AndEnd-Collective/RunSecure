package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeClient creates a test Client pointing at the given server URL with a
// temp PAT file (mode 0400).
func makeClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))
	c, err := NewClient(serverURL, patFile)
	require.NoError(t, err)
	return c
}

func TestGetRunnerYML_200_DecodesContent(t *testing.T) {
	yamlContent := "runtime: node:24\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/o/r/contents/.github/runner.yml", r.URL.Path)
		require.Equal(t, "Bearer ghp_test", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("If-None-Match"), "no ETag on first request")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResponse{
			Content:  encoded,
			Encoding: "base64",
		})
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	body, newETag, notModified, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.NoError(t, err)
	require.False(t, notModified)
	require.Equal(t, `"abc123"`, newETag)
	require.Equal(t, []byte(yamlContent), body)
}

func TestGetRunnerYML_304_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, `"abc123"`, r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	body, newETag, notModified, err := c.GetRunnerYML(context.Background(), "o/r", `"abc123"`)
	require.NoError(t, err)
	require.True(t, notModified)
	require.Nil(t, body)
	require.Empty(t, newETag)
}

func TestGetRunnerYML_NonOKStatus_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestGetRunnerYML_InvalidJSON_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode JSON")
}

func TestGetRunnerYML_UnexpectedEncoding_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResponse{
			Content:  "aGVsbG8=",
			Encoding: "utf-8",
		})
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "encoding")
}

func TestGetRunnerYML_InvalidBase64_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResponse{
			Content:  "!!!not-valid-base64!!!",
			Encoding: "base64",
		})
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "base64")
}

func TestGetRunnerYML_SendsETagWhenProvided(t *testing.T) {
	yamlContent := "runtime: python:3.12\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	var receivedETag string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedETag = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"newetag"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResponse{
			Content:  encoded,
			Encoding: "base64",
		})
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, newETag, _, err := c.GetRunnerYML(context.Background(), "o/r", `"oldetag"`)
	require.NoError(t, err)
	require.Equal(t, `"oldetag"`, receivedETag, "client must forward ETag in If-None-Match")
	require.Equal(t, `"newetag"`, newETag)
}

// TestGetRunnerYML_Base64WithNewlines verifies that GitHub's multi-line base64
// encoding (RFC 2045 line-folded) is handled correctly.
func TestGetRunnerYML_Base64WithNewlines(t *testing.T) {
	yamlContent := "runtime: node:24\nlabels:\n  - self-hosted\n"
	// Simulate GitHub's line-folded encoding (every 60 chars + \n).
	raw := base64.StdEncoding.EncodeToString([]byte(yamlContent))
	folded := ""
	for i := 0; i < len(raw); i += 60 {
		end := i + 60
		if end > len(raw) {
			end = len(raw)
		}
		folded += raw[i:end] + "\n"
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(contentsResponse{
			Content:  folded,
			Encoding: "base64",
		})
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	body, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.NoError(t, err)
	require.Equal(t, []byte(yamlContent), body)
}

func TestGetRunnerYML_NetworkError(t *testing.T) {
	// Point at a server that immediately closes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // Close before request.

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
}

// TestGetRunnerYML_MaybeReloadFails verifies that a PAT file deletion between
// client construction and the first GetRunnerYML call causes an error before
// any HTTP request is made.
func TestGetRunnerYML_MaybeReloadFails(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))

	c, err := NewClient("http://127.0.0.1:9999", patFile)
	require.NoError(t, err)

	// Delete the PAT file and force mtime mismatch by removing the file —
	// maybeReload will call Stat which returns an error.
	require.NoError(t, os.Remove(patFile))

	_, _, _, err = c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err, "GetRunnerYML must fail when maybeReload cannot stat the PAT file")
}

// TestGetRunnerYML_BadBaseURL covers the http.NewRequestWithContext error
// branch inside GetRunnerYML. A malformed base URL (non-ASCII control byte)
// causes NewRequestWithContext to return an error before any network I/O.
func TestGetRunnerYML_BadBaseURL(t *testing.T) {
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_test"), 0o400))
	// Use a URL that is syntactically accepted by url.Parse but rejected by
	// http.NewRequestWithContext because it contains a control character.
	c, err := NewClient("http://host\x00bad", patFile)
	require.NoError(t, err)
	_, _, _, err = c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
}

// TestGetRunnerYML_BodyReadError covers the io.ReadAll error branch in
// GetRunnerYML. The httptest server hijacks the connection and sends a 200
// response with Content-Length: 1000 but only writes 5 bytes before closing,
// causing the client's io.ReadAll to return io.ErrUnexpectedEOF.
func TestGetRunnerYML_BodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		require.True(t, ok, "httptest.Server must support http.Hijacker")
		conn, bufrw, err := hj.Hijack()
		require.NoError(t, err)
		// Advertise a 1000-byte body but write only 5 bytes, then close.
		// The client's io.ReadAll will receive fewer bytes than Content-Length
		// and return io.ErrUnexpectedEOF.
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: application/json\r\n\r\n")
		_, _ = bufrw.WriteString("short")
		_ = bufrw.Flush()
		conn.Close()
	}))
	defer srv.Close()

	c := makeClient(t, srv.URL)
	_, _, _, err := c.GetRunnerYML(context.Background(), "o/r", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "read body")
}
