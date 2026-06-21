// Package config loads socket-proxy configuration from environment variables.
// The set of knobs is intentionally tiny — the proxy's behavior is mostly
// determined by hard-coded refuse rules in internal/proxy/validate.go.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	DockerSock        string // path to docker.sock on the host (bind-mounted)
	ListenAddr        string // tcp listen address (default :2375)
	AllowedImagesFile string // path to digest allowlist file

	TLSMode         string // "plaintext" (default) | "mtls"
	TLSCertFile     string // server certificate (PEM)
	TLSKeyFile      string // server private key (PEM)
	TLSClientCAFile string // CA cert used to verify client certs (PEM)
	TLSListenAddr   string // TLS listener address (default :2376)
}

const (
	defaultListen        = ":2375"
	defaultAllowedImages = "/etc/runsecure/socket-proxy/allowed-images.txt"
	defaultTLSMode       = "plaintext"
	defaultTLSListen     = ":2376"
)

func FromEnv() (Config, error) {
	c := Config{
		DockerSock:        os.Getenv("RUNSECURE_DOCKER_SOCK"),
		ListenAddr:        envOr("RUNSECURE_LISTEN_ADDR", defaultListen),
		AllowedImagesFile: envOr("RUNSECURE_ALLOWED_IMAGES_FILE", defaultAllowedImages),

		TLSMode:         envOr("RUNSECURE_SP_TLS_MODE", defaultTLSMode),
		TLSCertFile:     os.Getenv("RUNSECURE_SP_TLS_CERT"),
		TLSKeyFile:      os.Getenv("RUNSECURE_SP_TLS_KEY"),
		TLSClientCAFile: os.Getenv("RUNSECURE_SP_TLS_CLIENT_CA"),
		TLSListenAddr:   envOr("RUNSECURE_SP_TLS_LISTEN", defaultTLSListen),
	}
	if c.DockerSock == "" {
		return Config{}, errors.New("RUNSECURE_DOCKER_SOCK is required")
	}
	switch c.TLSMode {
	case "plaintext":
		// no extra validation required
	case "mtls":
		if c.TLSCertFile == "" || c.TLSKeyFile == "" || c.TLSClientCAFile == "" {
			return Config{}, errors.New("mtls mode requires TLS_CERT, TLS_KEY, and TLS_CLIENT_CA")
		}
	default:
		return Config{}, fmt.Errorf("invalid TLS mode: %s", c.TLSMode)
	}
	return c, nil
}

// BuildTLSConfig returns a *tls.Config suitable for use as a server's TLS
// configuration. Returns nil, nil when TLSMode is "plaintext".
func (c Config) BuildTLSConfig() (*tls.Config, error) {
	if c.TLSMode == "plaintext" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	caPEM, err := os.ReadFile(c.TLSClientCAFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse client CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
