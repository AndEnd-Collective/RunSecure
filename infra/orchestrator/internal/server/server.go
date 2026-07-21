package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
)

// Server bundles the two HTTP listeners (healthz + metrics/snapshot).
type Server struct {
	healthzAddr string
	debugAddr   string
	healthz     http.Handler
	readyz      http.Handler
	metrics     http.Handler
	snapshot    http.Handler
}

// AllDeps is the union of all server-side dependency interfaces.
type AllDeps interface {
	HealthDeps
	ReadyDeps
	MetricsDeps
	SnapshotDeps
}

// HTTP server timeouts. Accessor funcs (not consts) so mutation testing
// can observe the multiplication operators inside a function body.
func HTTPReadHeaderTimeout() time.Duration { return 2 * time.Second }
func HTTPReadTimeout() time.Duration       { return 10 * time.Second }
func HTTPWriteTimeout() time.Duration      { return 10 * time.Second }
func HTTPIdleTimeout() time.Duration       { return 60 * time.Second }
func HTTPShutdownTimeout() time.Duration   { return 5 * time.Second }

// New constructs a Server. healthzAddr defaults to :8080, debugAddr to :8081.
func New(healthzAddr, debugAddr string, deps AllDeps, em *cornerstone.Emitter) *Server {
	if healthzAddr == "" {
		healthzAddr = ":8080"
	}
	if debugAddr == "" {
		debugAddr = ":8081"
	}
	return &Server{
		healthzAddr: healthzAddr,
		debugAddr:   debugAddr,
		healthz:     NewHealthz(deps, em),
		readyz:      NewReadyz(deps),
		metrics:     NewMetrics(deps),
		snapshot:    NewSnapshot(deps),
	}
}

func (s *Server) httpServers() (*http.Server, *http.Server) {
	healthzMux := http.NewServeMux()
	healthzMux.Handle("/healthz", s.healthz)
	healthzMux.Handle("/readyz", s.readyz)

	debugMux := http.NewServeMux()
	debugMux.Handle("/metrics", s.metrics)
	debugMux.Handle("/state/snapshot", s.snapshot)

	healthzSrv := &http.Server{
		Addr:              s.healthzAddr,
		Handler:           healthzMux,
		ReadHeaderTimeout: HTTPReadHeaderTimeout(),
		ReadTimeout:       HTTPReadTimeout(),
		WriteTimeout:      HTTPWriteTimeout(),
		IdleTimeout:       HTTPIdleTimeout(),
	}
	debugSrv := &http.Server{
		Addr:              s.debugAddr,
		Handler:           debugMux,
		ReadHeaderTimeout: HTTPReadHeaderTimeout(),
		ReadTimeout:       HTTPReadTimeout(),
		WriteTimeout:      HTTPWriteTimeout(),
		IdleTimeout:       HTTPIdleTimeout(),
	}
	return healthzSrv, debugSrv
}

// Start binds both management listeners synchronously, then serves them in
// the background. A successful return guarantees that supervisors can reach
// /healthz before the caller begins potentially slow cold-start reconciliation.
// The returned channel yields exactly one terminal server result.
func (s *Server) Start(ctx context.Context) (<-chan error, error) {
	healthzListener, err := net.Listen("tcp", s.healthzAddr)
	if err != nil {
		return nil, fmt.Errorf("health listener %s: %w", s.healthzAddr, err)
	}
	debugListener, err := net.Listen("tcp", s.debugAddr)
	if err != nil {
		_ = healthzListener.Close()
		return nil, fmt.Errorf("debug listener %s: %w", s.debugAddr, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx, healthzListener, debugListener)
		close(done)
	}()
	return done, nil
}

// Run starts both listeners and blocks until ctx is cancelled, then shuts
// them down gracefully.
func (s *Server) Run(ctx context.Context) error {
	done, err := s.Start(ctx)
	if err != nil {
		return err
	}
	return <-done
}

func (s *Server) serve(
	ctx context.Context,
	healthzListener net.Listener,
	debugListener net.Listener,
) error {
	healthzSrv, debugSrv := s.httpServers()

	errCh := make(chan error, 2)
	go func() { errCh <- healthzSrv.Serve(healthzListener) }()
	go func() { errCh <- debugSrv.Serve(debugListener) }()

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(), HTTPShutdownTimeout(),
		)
		defer cancel()
		_ = healthzSrv.Shutdown(shutdownCtx)
		_ = debugSrv.Shutdown(shutdownCtx)
	}

	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err := <-errCh:
		shutdown()
		return err
	}
}
