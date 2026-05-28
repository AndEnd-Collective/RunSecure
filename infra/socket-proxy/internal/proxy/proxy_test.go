package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/stretchr/testify/require"
)

// Mutation kill: proxy.go transportIdleConnTimeout — `60 * time.Second`.
// Exact-value assert covers the multiplication so the mutation lands in
// a tracked function body.
func TestTransportIdleConnTimeout(t *testing.T) {
	require.Equal(t, 60*time.Second, transportIdleConnTimeout())
}

// startFakeDockerd creates a Unix socket that serves canned 200 responses
// for any request. Returns the socket path.
//
// Note: macOS sockaddr_un.sun_path is 104 bytes. Test names in t.TempDir()
// paths can exceed this, so we use a short os.MkdirTemp pattern instead.
func startFakeDockerd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rs-d")
	require.NoError(t, err)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close(); _ = os.RemoveAll(dir) })
	return sock
}

func setupServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dockerSock := startFakeDockerd(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	srv := httptest.NewServer(New(dockerSock, allow))
	t.Cleanup(srv.Close)
	return srv, dockerSock
}

func TestServer_AllowedRoute_PassesThroughToDockerd(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Get(srv.URL + "/v1.43/info")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), `"ok":true`)
}

func TestServer_DisallowedRoute_403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/containers/abc/exec", "application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	var denied denyBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&denied))
	require.Equal(t, "route_not_allowed", denied.Code)
}

func TestServer_ContainerCreate_PrivilegedRejected(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Image": "ghcr.io/test/runner@sha256:ff",
		"User":  "1001:0",
		"HostConfig": map[string]any{
			"Privileged":  true,
			"CapDrop":     []any{"ALL"},
			"SecurityOpt": []any{"no-new-privileges:true"},
		},
	})
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_NetworkCreate_NotInternalRejected(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{"Name": "x", "Driver": "bridge", "Internal": false})
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_ContainerCreate_HappyPath(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Image": "ghcr.io/test/runner@sha256:ff",
		"User":  "1001:0",
		"HostConfig": map[string]any{
			"CapDrop":     []any{"ALL"},
			"SecurityOpt": []any{"no-new-privileges:true"},
			"NetworkMode": "rs-net-test",
		},
	})
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_NetworkCreate_HappyPath(t *testing.T) {
	srv, _ := setupServer(t)
	body, _ := json.Marshal(map[string]any{
		"Name":       "rs-net-test",
		"Driver":     "bridge",
		"Internal":   true,
		"Attachable": false,
	})
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_SetLogger_Captures(t *testing.T) {
	logged := 0
	s := New("", nil)
	s.SetLogger(func(format string, args ...any) { logged++ })
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/disallowed", nil)
	s.ServeHTTP(rr, r)
	require.Equal(t, 1, logged)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestServer_ContainerCreate_MalformedBodyReturns403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/containers/create", "application/json", bytes.NewReader([]byte("{ not json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestServer_NetworkCreate_MalformedBodyReturns403(t *testing.T) {
	srv, _ := setupServer(t)
	resp, err := http.Post(srv.URL+"/v1.43/networks/create", "application/json", bytes.NewReader([]byte("not json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// errReader fails on first Read. Used to exercise the body-read-failed
// path of ServeHTTP via direct handler invocation (not over the wire —
// net/http aborts the request before the response is observable).
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, ioErrBoom{} }
func (errReader) Close() error               { return nil }

type ioErrBoom struct{}

func (ioErrBoom) Error() string { return "boom" }

func TestServer_ContainerCreate_BodyReadFails_400(t *testing.T) {
	dockerSock := startFakeDockerd(t)
	allow := loadAllowAllImagesForServer(t)
	s := New(dockerSock, allow)

	r := httptest.NewRequest(http.MethodPost, "/v1.43/containers/create", errReader{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestServer_NetworkCreate_BodyReadFails_400(t *testing.T) {
	dockerSock := startFakeDockerd(t)
	allow := loadAllowAllImagesForServer(t)
	s := New(dockerSock, allow)

	r := httptest.NewRequest(http.MethodPost, "/v1.43/networks/create", errReader{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

// loadAllowAllImagesForServer is a tiny helper to build a digest allowlist
// without going through setupServer (which also starts an httptest server).
func loadAllowAllImagesForServer(t *testing.T) *imageallow.Allowlist {
	t.Helper()
	dir, err := os.MkdirTemp("", "rs-a")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	return allow
}

func TestServer_UpstreamError_502(t *testing.T) {
	// Point at a nonexistent socket path so the reverse-proxy transport fails.
	allowDir, err := os.MkdirTemp("", "rs-a")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(allowDir) })
	path := filepath.Join(allowDir, "allow.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/test/runner@sha256:ff\n"), 0o644))
	allow, err := imageallow.Load(path)
	require.NoError(t, err)
	srv := httptest.NewServer(New("/nonexistent/sock", allow))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1.43/info")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}
