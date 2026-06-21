package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromEnv_Defaults(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_LISTEN_ADDR", "")
	t.Setenv("RUNSECURE_ALLOWED_IMAGES_FILE", "")

	c, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, "/var/run/docker.sock", c.DockerSock)
	require.Equal(t, ":2375", c.ListenAddr)
	require.Equal(t, "/etc/runsecure/socket-proxy/allowed-images.txt", c.AllowedImagesFile)
}

func TestFromEnv_RejectsEmptyDockerSock(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "")
	_, err := FromEnv()
	require.ErrorContains(t, err, "RUNSECURE_DOCKER_SOCK")
}

func TestFromEnv_OverridesFromEnv(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/tmp/d.sock")
	t.Setenv("RUNSECURE_LISTEN_ADDR", ":8080")
	t.Setenv("RUNSECURE_ALLOWED_IMAGES_FILE", "/etc/foo.txt")
	c, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, "/tmp/d.sock", c.DockerSock)
	require.Equal(t, ":8080", c.ListenAddr)
	require.Equal(t, "/etc/foo.txt", c.AllowedImagesFile)
}

// --- TLS config field tests ---

func TestFromEnv_TLS_Defaults(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "")
	t.Setenv("RUNSECURE_SP_TLS_CERT", "")
	t.Setenv("RUNSECURE_SP_TLS_KEY", "")
	t.Setenv("RUNSECURE_SP_TLS_CLIENT_CA", "")
	t.Setenv("RUNSECURE_SP_TLS_LISTEN", "")
	c, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, "plaintext", c.TLSMode)
	require.Equal(t, ":2376", c.TLSListenAddr)
	require.Empty(t, c.TLSCertFile)
}

func TestFromEnv_TLS_Overrides(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "mtls")
	t.Setenv("RUNSECURE_SP_TLS_CERT", "/etc/certs/server.crt")
	t.Setenv("RUNSECURE_SP_TLS_KEY", "/etc/certs/server.key")
	t.Setenv("RUNSECURE_SP_TLS_CLIENT_CA", "/etc/certs/ca.crt")
	t.Setenv("RUNSECURE_SP_TLS_LISTEN", ":9443")
	c, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, "mtls", c.TLSMode)
	require.Equal(t, "/etc/certs/server.crt", c.TLSCertFile)
	require.Equal(t, "/etc/certs/server.key", c.TLSKeyFile)
	require.Equal(t, "/etc/certs/ca.crt", c.TLSClientCAFile)
	require.Equal(t, ":9443", c.TLSListenAddr)
}

func TestFromEnv_TLS_MtlsMissingCert(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "mtls")
	t.Setenv("RUNSECURE_SP_TLS_CERT", "")
	t.Setenv("RUNSECURE_SP_TLS_KEY", "/etc/certs/server.key")
	t.Setenv("RUNSECURE_SP_TLS_CLIENT_CA", "/etc/certs/ca.crt")
	_, err := FromEnv()
	require.ErrorContains(t, err, "mtls mode requires")
}

func TestFromEnv_TLS_MtlsMissingKey(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "mtls")
	t.Setenv("RUNSECURE_SP_TLS_CERT", "/etc/certs/server.crt")
	t.Setenv("RUNSECURE_SP_TLS_KEY", "")
	t.Setenv("RUNSECURE_SP_TLS_CLIENT_CA", "/etc/certs/ca.crt")
	_, err := FromEnv()
	require.ErrorContains(t, err, "mtls mode requires")
}

func TestFromEnv_TLS_MtlsMissingCA(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "mtls")
	t.Setenv("RUNSECURE_SP_TLS_CERT", "/etc/certs/server.crt")
	t.Setenv("RUNSECURE_SP_TLS_KEY", "/etc/certs/server.key")
	t.Setenv("RUNSECURE_SP_TLS_CLIENT_CA", "")
	_, err := FromEnv()
	require.ErrorContains(t, err, "mtls mode requires")
}

func TestFromEnv_TLS_InvalidMode(t *testing.T) {
	t.Setenv("RUNSECURE_DOCKER_SOCK", "/var/run/docker.sock")
	t.Setenv("RUNSECURE_SP_TLS_MODE", "foobar")
	_, err := FromEnv()
	require.ErrorContains(t, err, "invalid TLS mode")
}
