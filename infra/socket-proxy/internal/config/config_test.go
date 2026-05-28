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
