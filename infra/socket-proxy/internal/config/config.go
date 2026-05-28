// Package config loads socket-proxy configuration from environment variables.
// The set of knobs is intentionally tiny — the proxy's behavior is mostly
// determined by hard-coded refuse rules in internal/proxy/validate.go.
package config

import (
	"errors"
	"os"
)

type Config struct {
	DockerSock        string // path to docker.sock on the host (bind-mounted)
	ListenAddr        string // tcp listen address (default :2375)
	AllowedImagesFile string // path to digest allowlist file
}

const (
	defaultListen        = ":2375"
	defaultAllowedImages = "/etc/runsecure/socket-proxy/allowed-images.txt"
)

func FromEnv() (Config, error) {
	c := Config{
		DockerSock:        os.Getenv("RUNSECURE_DOCKER_SOCK"),
		ListenAddr:        envOr("RUNSECURE_LISTEN_ADDR", defaultListen),
		AllowedImagesFile: envOr("RUNSECURE_ALLOWED_IMAGES_FILE", defaultAllowedImages),
	}
	if c.DockerSock == "" {
		return Config{}, errors.New("RUNSECURE_DOCKER_SOCK is required")
	}
	return c, nil
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
