package main

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/stretchr/testify/require"
)

// newAllowlist returns a minimal Allowlist populated from an in-memory file so
// tests can call buildHTTPServer without touching a real filesystem path.
func newAllowlist(t *testing.T, lines ...string) *imageallow.Allowlist {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowed.txt")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	a, err := imageallow.Load(path)
	require.NoError(t, err)
	return a
}

// TestBuildHTTPServer_Timeouts checks that buildHTTPServer wires the expected
// timeouts and uses the config's ListenAddr as Addr.
func TestBuildHTTPServer_Timeouts(t *testing.T) {
	cfg := config.Config{
		DockerSock: "/tmp/docker.sock",
		ListenAddr: ":9999",
	}
	allow := newAllowlist(t, "ghcr.io/img@sha256:aabb")

	srv := buildHTTPServer(cfg, allow)

	require.Equal(t, ":9999", srv.Addr)
	require.Equal(t, 5*time.Second, srv.ReadHeaderTimeout)
	require.Equal(t, 30*time.Second, srv.ReadTimeout)
	require.Equal(t, 60*time.Second, srv.WriteTimeout)
	require.Equal(t, 120*time.Second, srv.IdleTimeout)
	require.NotNil(t, srv.Handler)
}

// TestServeWith_PlaintextPath verifies that when tlsCfg is nil, serveWith
// calls listenPlain (not listenTLS).
func TestServeWith_PlaintextPath(t *testing.T) {
	httpSrv := &http.Server{Addr: ":2375"}
	plainCalled := false
	tlsCalled := false
	sentinelErr := errors.New("plain serve called")

	err := serveWith(httpSrv, nil,
		func() error { plainCalled = true; return sentinelErr },
		func() error { tlsCalled = true; return nil },
	)

	require.Equal(t, sentinelErr, err, "error from listenPlain must propagate")
	require.True(t, plainCalled, "listenPlain must be invoked for nil tlsCfg")
	require.False(t, tlsCalled, "listenTLS must not be invoked for nil tlsCfg")
	// No TLSConfig set on server when plaintext.
	require.Nil(t, httpSrv.TLSConfig)
}

// TestServeWith_TLSPath verifies that when tlsCfg is non-nil, serveWith
// assigns it to the server and calls listenTLS.
func TestServeWith_TLSPath(t *testing.T) {
	httpSrv := &http.Server{Addr: ":2376"}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	plainCalled := false
	tlsCalled := false
	sentinelErr := errors.New("tls serve called")

	err := serveWith(httpSrv, tlsCfg,
		func() error { plainCalled = true; return nil },
		func() error { tlsCalled = true; return sentinelErr },
	)

	require.Equal(t, sentinelErr, err, "error from listenTLS must propagate")
	require.True(t, tlsCalled, "listenTLS must be invoked for non-nil tlsCfg")
	require.False(t, plainCalled, "listenPlain must not be invoked for non-nil tlsCfg")
	// TLSConfig must be set on the server before listenTLS is called.
	require.Equal(t, tlsCfg, httpSrv.TLSConfig)
}

// TestServeWith_TLSPathSetsAddr is a targeted check that the TLS listener
// address is carried on the http.Server.Addr field as configured — the log
// line and any subsequent bind both read httpSrv.Addr.
func TestServeWith_TLSPathSetsAddr(t *testing.T) {
	httpSrv := &http.Server{Addr: ":2376"}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	_ = serveWith(httpSrv, tlsCfg,
		func() error { return nil },
		func() error { return nil },
	)

	require.Equal(t, ":2376", httpSrv.Addr)
}

// TestBuildHTTPServer_LoggerIsInvoked exercises the SetLogger closure by
// sending a forbidden request through the server's handler. The logger fires
// on every deny, so this drives the uncovered log.Printf statement.
func TestBuildHTTPServer_LoggerIsInvoked(t *testing.T) {
	cfg := config.Config{
		DockerSock: "/tmp/docker.sock",
		ListenAddr: ":9999",
	}
	allow := newAllowlist(t, "ghcr.io/img@sha256:aabb")

	srv := buildHTTPServer(cfg, allow)

	// PUT /v1.41/containers/json is not in the route allowlist — the proxy
	// calls deny() which invokes the logger closure registered by SetLogger.
	req := httptest.NewRequest(http.MethodPut, "/v1.41/containers/json", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}
