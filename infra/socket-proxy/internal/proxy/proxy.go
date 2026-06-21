package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
)

// Server is the docker-socket-proxy HTTP server.
type Server struct {
	rp        *httputil.ReverseProxy
	images    *imageallow.Allowlist
	logger    func(format string, args ...any)
	egressNet string // value of RUNSECURE_EGRESS_NETWORK; "" disables egress gate
}

// transportIdleConnTimeout is the per-connection idle timeout for the
// reverse-proxy's HTTP transport to dockerd. Accessor func (not const)
// so mutation testing observes the multiplication operator.
func transportIdleConnTimeout() time.Duration {
	return 60 * time.Second
}

// New constructs a Server. dockerSock is the path to /var/run/docker.sock
// (or another UDS path the socket-proxy bind-mounts).
//
// The egress-network name is read from RUNSECURE_EGRESS_NETWORK at
// construction time so that the gate is active from the first request. An
// empty env var disables the gate (useful in development / test environments
// that do not use a named egress network).
func New(dockerSock string, images *imageallow.Allowlist) *Server {
	target, _ := url.Parse("http://docker") // hostname is arbitrary; dialer overrides
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", dockerSock)
		},
		MaxIdleConns:        16,
		IdleConnTimeout:     transportIdleConnTimeout(),
		TLSHandshakeTimeout: 0,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
	}
	return &Server{
		rp:        rp,
		images:    images,
		logger:    func(string, ...any) {},
		egressNet: os.Getenv("RUNSECURE_EGRESS_NETWORK"),
	}
}

// SetLogger replaces the default no-op logger.
func (s *Server) SetLogger(fn func(format string, args ...any)) {
	s.logger = fn
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !RouteAllowed(r.Method, r.URL.Path) {
		s.deny(w, "route_not_allowed", r.Method+" "+r.URL.Path, http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost && containerCreatePath(r.URL.Path) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			s.deny(w, "body_read_failed", err.Error(), http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		if err := ValidateContainerCreate(body, s.images, s.egressNet); err != nil {
			s.deny(w, "validation_failed", err.Error(), http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if r.Method == http.MethodPost && networkCreatePath(r.URL.Path) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			s.deny(w, "body_read_failed", err.Error(), http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		if err := ValidateNetworkCreate(body); err != nil {
			s.deny(w, "validation_failed", err.Error(), http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	s.rp.ServeHTTP(w, r)
}

type denyBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (s *Server) deny(w http.ResponseWriter, code, detail string, status int) {
	s.logger("deny code=%s detail=%s status=%d", code, detail, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(denyBody{Code: code, Detail: detail})
}

// containerCreatePath returns true if path is /v*/containers/create.
func containerCreatePath(path string) bool {
	stripped := versionPrefix.ReplaceAllString(path, "")
	return stripped == "/containers/create"
}

func networkCreatePath(path string) bool {
	stripped := versionPrefix.ReplaceAllString(path, "")
	return stripped == "/networks/create"
}

// ErrPolicyDenied is the sentinel for callers that want to distinguish a
// deny-by-policy from a transport error.
var ErrPolicyDenied = errors.New("policy denied")
