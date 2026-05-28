package main

import (
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
	allow, err := imageallow.Load(cfg.AllowedImagesFile)
	if err != nil {
		return err
	}
	log.Printf("socket-proxy: listening on %s (image-allowlist=%d entries)", cfg.ListenAddr, allow.Size())

	srv := proxy.New(cfg.DockerSock, allow)
	srv.SetLogger(func(f string, a ...any) { log.Printf("socket-proxy: "+f, a...) })

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return httpSrv.ListenAndServe()
}
