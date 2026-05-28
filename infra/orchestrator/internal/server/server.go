package server

import (
	"context"
	"net/http"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/cornerstone"
)

// Server bundles the two HTTP listeners (healthz + metrics/snapshot).
type Server struct {
	healthzAddr string
	debugAddr   string
	healthz     http.Handler
	metrics     http.Handler
	snapshot    http.Handler
}

// AllDeps is the union of all server-side dependency interfaces.
type AllDeps interface {
	HealthDeps
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
		metrics:     NewMetrics(deps),
		snapshot:    NewSnapshot(deps),
	}
}

// Run starts both listeners and blocks until ctx is cancelled, then shuts
// them down gracefully.
func (s *Server) Run(ctx context.Context) error {
	healthzMux := http.NewServeMux()
	healthzMux.Handle("/healthz", s.healthz)

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

	errCh := make(chan error, 2)
	go func() { errCh <- healthzSrv.ListenAndServe() }()
	go func() { errCh <- debugSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), HTTPShutdownTimeout())
		defer cancel()
		_ = healthzSrv.Shutdown(shutdownCtx)
		_ = debugSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
