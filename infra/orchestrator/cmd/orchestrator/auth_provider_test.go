package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/config"
	"github.com/stretchr/testify/require"
)

// writePATFile creates a mode-0400 PAT file for testing.
func writePATFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	require.NoError(t, os.Chmod(p, 0o400))
	return p
}

// writeRSAKeyFile generates an RSA-2048 key and writes it as a mode-0400 PEM file.
func writeRSAKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	dir := t.TempDir()
	p := filepath.Join(dir, "app.pem")
	require.NoError(t, os.WriteFile(p, pemBytes, 0o600))
	require.NoError(t, os.Chmod(p, 0o400))
	return p
}

// TestBuildAuthProvider_PAT verifies that auth.type=pat returns a working
// provider without error.
func TestBuildAuthProvider_PAT(t *testing.T) {
	patFile := writePATFile(t, "ghp_test")
	s := &config.Scope{
		Auth: config.AuthBlock{
			Type:    "pat",
			PATFile: patFile,
		},
	}
	p, err := buildAuthProvider(s, "https://api.github.com")
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestBuildAuthProvider_PAT_MissingFile verifies that a missing PAT file
// propagates an error from NewPATProvider.
func TestBuildAuthProvider_PAT_MissingFile(t *testing.T) {
	s := &config.Scope{
		Auth: config.AuthBlock{
			Type:    "pat",
			PATFile: "/nonexistent/pat",
		},
	}
	_, err := buildAuthProvider(s, "https://api.github.com")
	require.Error(t, err)
}

// TestBuildAuthProvider_GitHubApp verifies that auth.type=github_app returns a
// working provider without error when given a valid key file.
func TestBuildAuthProvider_GitHubApp(t *testing.T) {
	keyFile := writeRSAKeyFile(t)
	s := &config.Scope{
		Auth: config.AuthBlock{
			Type:           "github_app",
			AppID:          42,
			InstallationID: 99,
			PrivateKeyFile: keyFile,
		},
	}
	p, err := buildAuthProvider(s, "https://api.github.com")
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestBuildAuthProvider_GitHubApp_MissingKeyFile verifies that a missing key
// file propagates an error from NewGitHubAppProvider.
func TestBuildAuthProvider_GitHubApp_MissingKeyFile(t *testing.T) {
	s := &config.Scope{
		Auth: config.AuthBlock{
			Type:           "github_app",
			AppID:          1,
			InstallationID: 2,
			PrivateKeyFile: "/nonexistent/key.pem",
		},
	}
	_, err := buildAuthProvider(s, "https://api.github.com")
	require.Error(t, err)
}

// TestBuildAuthProvider_UnknownType verifies that an unrecognised auth.type
// returns an error (defensive guard; Validate would have caught it first).
func TestBuildAuthProvider_UnknownType(t *testing.T) {
	s := &config.Scope{
		Auth: config.AuthBlock{Type: "oauth"},
	}
	_, err := buildAuthProvider(s, "https://api.github.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown auth.type")
}
