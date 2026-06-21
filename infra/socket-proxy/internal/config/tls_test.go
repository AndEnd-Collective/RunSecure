package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// generateCA generates an in-memory CA key+cert and writes them to temp files.
// Returns (caKey, caCert, caCertPEMFile, error).
func generateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDERBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDERBytes)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDERBytes})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, caCertPEM, 0o600))

	return caKey, caCert, caFile
}

// generateLeafCert generates a leaf cert signed by the given CA.
// Returns (certFile, keyFile).
func generateLeafCert(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, isServer bool) (certFile, keyFile string) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isServer {
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, cn+".crt")
	keyFile = filepath.Join(dir, cn+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return certFile, keyFile
}

func TestBuildTLSConfig_Plaintext(t *testing.T) {
	c := Config{TLSMode: "plaintext"}
	tlsCfg, err := c.BuildTLSConfig()
	require.NoError(t, err)
	require.Nil(t, tlsCfg)
}

func TestBuildTLSConfig_Mtls(t *testing.T) {
	caKey, caCert, caFile := generateCA(t)
	certFile, keyFile := generateLeafCert(t, "server", caKey, caCert, true)

	c := Config{
		TLSMode:         "mtls",
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: caFile,
	}
	tlsCfg, err := c.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsCfg.ClientAuth)
	require.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
	require.NotNil(t, tlsCfg.ClientCAs)
	require.Len(t, tlsCfg.Certificates, 1)
}

func TestBuildTLSConfig_MissingCertFile(t *testing.T) {
	caKey, caCert, caFile := generateCA(t)
	_, keyFile := generateLeafCert(t, "server", caKey, caCert, true)

	c := Config{
		TLSMode:         "mtls",
		TLSCertFile:     "/nonexistent/cert.crt",
		TLSKeyFile:      keyFile,
		TLSClientCAFile: caFile,
	}
	_, err := c.BuildTLSConfig()
	require.Error(t, err)
}

func TestBuildTLSConfig_MissingKeyFile(t *testing.T) {
	caKey, caCert, caFile := generateCA(t)
	certFile, _ := generateLeafCert(t, "server", caKey, caCert, true)

	c := Config{
		TLSMode:         "mtls",
		TLSCertFile:     certFile,
		TLSKeyFile:      "/nonexistent/key.key",
		TLSClientCAFile: caFile,
	}
	_, err := c.BuildTLSConfig()
	require.Error(t, err)
}

func TestBuildTLSConfig_MissingCAFile(t *testing.T) {
	caKey, caCert, _ := generateCA(t)
	certFile, keyFile := generateLeafCert(t, "server", caKey, caCert, true)

	c := Config{
		TLSMode:         "mtls",
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: "/nonexistent/ca.crt",
	}
	_, err := c.BuildTLSConfig()
	require.Error(t, err)
}

func TestBuildTLSConfig_InvalidCAContent(t *testing.T) {
	caKey, caCert, _ := generateCA(t)
	certFile, keyFile := generateLeafCert(t, "server", caKey, caCert, true)

	dir := t.TempDir()
	badCAFile := filepath.Join(dir, "bad-ca.crt")
	require.NoError(t, os.WriteFile(badCAFile, []byte("not valid pem"), 0o600))

	c := Config{
		TLSMode:         "mtls",
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: badCAFile,
	}
	_, err := c.BuildTLSConfig()
	require.ErrorContains(t, err, "failed to parse client CA cert")
}

func TestBuildTLSConfig_EndToEnd_ClientWithCertAccepted(t *testing.T) {
	caKey, caCert, caFile := generateCA(t)
	serverCertFile, serverKeyFile := generateLeafCert(t, "server", caKey, caCert, true)
	clientCertFile, clientKeyFile := generateLeafCert(t, "client", caKey, caCert, false)

	serverCfg := Config{
		TLSMode:         "mtls",
		TLSCertFile:     serverCertFile,
		TLSKeyFile:      serverKeyFile,
		TLSClientCAFile: caFile,
	}
	tlsCfg, err := serverCfg.BuildTLSConfig()
	require.NoError(t, err)

	// Build a test server with mTLS
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// Build client CA pool from caFile
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	// Client WITH cert — should succeed
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	require.NoError(t, err)
	goodClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
	resp, err := goodClient.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestBuildTLSConfig_EndToEnd_ClientWithoutCertRejected(t *testing.T) {
	caKey, caCert, caFile := generateCA(t)
	serverCertFile, serverKeyFile := generateLeafCert(t, "server", caKey, caCert, true)

	serverCfg := Config{
		TLSMode:         "mtls",
		TLSCertFile:     serverCertFile,
		TLSKeyFile:      serverKeyFile,
		TLSClientCAFile: caFile,
	}
	tlsCfg, err := serverCfg.BuildTLSConfig()
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	// Client WITHOUT cert — should be rejected
	badClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}
	_, err = badClient.Get(srv.URL)
	require.Error(t, err, "client without cert must be rejected by mTLS server")
}
