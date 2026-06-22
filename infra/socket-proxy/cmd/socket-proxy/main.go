package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/config"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "socket-proxy:", err)
		os.Exit(1)
	}
}

//coverage:ignore main entrypoint — tested via integration tests
func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	// LoadWithExtra merges the baked allowlist with an optional operator-supplied
	// file (RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE). The extra file solves the
	// release bootstrap problem: newly-published image digests can't be baked
	// into the socket-proxy image before that image exists (#54 fix 3).
	allow, err := imageallow.LoadWithExtra(cfg.AllowedImagesFile, cfg.AllowedImagesExtraFile)
	if err != nil {
		return err
	}
	if cfg.AllowedImagesExtraFile != "" {
		log.Printf("socket-proxy: extra allowlist=%s", cfg.AllowedImagesExtraFile)
	}
	log.Printf("socket-proxy: listening on %s (image-allowlist=%d entries)", cfg.ListenAddr, allow.Size())

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		return err
	}

	httpSrv := buildHTTPServer(cfg, allow)
	return serveWith(httpSrv, tlsCfg,
		func() error { return httpSrv.ListenAndServe() },
		func() error { return httpSrv.ListenAndServeTLS("", "") },
	)
}

// buildHTTPServer constructs the http.Server from config and the image
// allowlist. It is extracted so unit tests can verify the server fields
// (timeouts, handler) without binding a real socket.
func buildHTTPServer(cfg config.Config, allow *imageallow.Allowlist) *http.Server {
	srv := proxy.New(cfg.DockerSock, allow)
	srv.SetLogger(func(f string, a ...any) { log.Printf("socket-proxy: "+f, a...) })
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// serveWith selects the serve path based on whether tlsCfg is nil.
// listenPlain and listenTLS are injected so tests can verify which path is
// chosen without binding a real port. In production both are closures over
// httpSrv's own methods.
func serveWith(httpSrv *http.Server, tlsCfg *tls.Config, listenPlain, listenTLS func() error) error {
	if tlsCfg != nil {
		httpSrv.TLSConfig = tlsCfg
		log.Printf("socket-proxy: TLS listener on %s", httpSrv.Addr)
		return listenTLS()
	}
	return listenPlain()
}
