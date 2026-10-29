package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/cornerstone"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		_ = cornerstone.NewEmitter(os.Stdout).Emit(cornerstone.ProcessFailed, cornerstone.Fields{Reason: "process_failed"})
		os.Exit(1)
	}
}

//coverage:ignore main entrypoint — tested via integration tests
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	em := cornerstone.NewEmitter(os.Stdout)
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	// LoadWithExtra merges the baked allowlist with an optional operator-supplied
	// custom-image file (RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE). Matching release
	// proxy and runner digests are already present in the baked allowlist.
	allow, err := imageallow.LoadWithExtra(cfg.AllowedImagesFile, cfg.AllowedImagesExtraFile)
	if err != nil {
		return err
	}
	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		return err
	}

	httpSrv := buildHTTPServerWithEmitter(cfg, allow, em)
	_ = em.Emit(cornerstone.Started, cornerstone.Fields{ImageAllowlistEntries: allow.Size(), TLS: tlsCfg != nil})
	err = serveUntilCanceled(ctx, httpSrv, func() error {
		return serveWith(httpSrv, tlsCfg,
			func() error { return httpSrv.ListenAndServe() },
			func() error { return httpSrv.ListenAndServeTLS("", "") },
		)
	})
	_ = em.Emit(cornerstone.Stopped, cornerstone.Fields{})
	return err
}

// buildHTTPServer constructs the http.Server from config and the image
// allowlist. It is extracted so unit tests can verify the server fields
// (timeouts, handler) without binding a real socket.
func buildHTTPServer(cfg config.Config, allow *imageallow.Allowlist) *http.Server {
	return buildHTTPServerWithEmitter(cfg, allow, cornerstone.NewEmitter(os.Stdout))
}

func buildHTTPServerWithEmitter(cfg config.Config, allow *imageallow.Allowlist, em *cornerstone.Emitter) *http.Server {
	srv := proxy.New(cfg.DockerSock, allow)
	srv.SetEventLogger(func(kind, code string, status int) {
		event := cornerstone.Denied
		if kind == "upstream_failed" {
			event = cornerstone.UpstreamFailed
		}
		_ = em.Emit(event, cornerstone.Fields{Reason: code, Status: status})
	})
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(em, "", 0),
	}
}

// serveWith selects the serve path based on whether tlsCfg is nil.
// listenPlain and listenTLS are injected so tests can verify which path is
// chosen without binding a real port. In production both are closures over
// httpSrv's own methods.
func serveWith(httpSrv *http.Server, tlsCfg *tls.Config, listenPlain, listenTLS func() error) error {
	if tlsCfg != nil {
		httpSrv.TLSConfig = tlsCfg
		return listenTLS()
	}
	return listenPlain()
}

func serveUntilCanceled(ctx context.Context, srv *http.Server, serve func() error) error {
	done := make(chan error, 1)
	go func() { done <- serve() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}
