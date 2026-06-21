package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/auth"
)

// generateTestKey generates an ephemeral RSA-2048 key for tests and writes it
// to a temp file with mode 0400. Returns the private key and the file path.
func generateTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "app.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return key, keyFile
}

// fakeInstallationServer returns an httptest.Server that responds to
// POST /app/installations/{id}/access_tokens with the given token and expiry.
// It records the Authorization header from each request and increments callCount.
func fakeInstallationServer(t *testing.T, tok string, expiresAt time.Time) (*httptest.Server, *[]string, *atomic.Int64) {
	t.Helper()
	var auths []string
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      tok,
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &auths, &calls
}

// decodeJWT splits a JWT into header+claims and decodes them as JSON maps.
func decodeJWT(t *testing.T, jwt string) (header map[string]any, claims map[string]any) {
	t.Helper()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts (want 3)", len(parts))
	}
	for i, name := range []string{"header", "claims"} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatalf("decode JWT %s: %v", name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal JWT %s: %v", name, err)
		}
		if i == 0 {
			header = m
		} else {
			claims = m
		}
	}
	return header, claims
}

// TestGitHubAppProvider_HappyPath verifies the full flow:
// - Token() returns the server's token
// - The posted JWT has alg=RS256, iss=appID, exp-iat <= 600s
// - A second call within validity does NOT re-POST (cache hit)
func TestGitHubAppProvider_HappyPath(t *testing.T) {
	const appID int64 = 42
	const installID int64 = 99

	expiry := time.Now().Add(time.Hour)
	srv, auths, calls := fakeInstallationServer(t, "ghs_testtoken", expiry)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(appID, installID, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	// First call — should POST and return the token.
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (first): %v", err)
	}
	if tok != "ghs_testtoken" {
		t.Errorf("Token() = %q; want %q", tok, "ghs_testtoken")
	}
	if calls.Load() != 1 {
		t.Errorf("calls after first Token() = %d; want 1", calls.Load())
	}

	// Assert JWT structure posted on the first call.
	if len(*auths) == 0 {
		t.Fatal("no Authorization header captured")
	}
	jwtStr := strings.TrimPrefix((*auths)[0], "Bearer ")
	header, jwtClaims := decodeJWT(t, jwtStr)

	if alg, _ := header["alg"].(string); alg != "RS256" {
		t.Errorf("JWT header alg = %q; want RS256", alg)
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("JWT header typ = %q; want JWT", typ)
	}

	iss, _ := jwtClaims["iss"].(float64)
	if int64(iss) != appID {
		t.Errorf("JWT claims iss = %v; want %d", jwtClaims["iss"], appID)
	}

	iat, _ := jwtClaims["iat"].(float64)
	exp, _ := jwtClaims["exp"].(float64)
	if delta := exp - iat; delta > 660 { // 10 min + 60s skew = 660s max
		t.Errorf("JWT exp-iat = %v; want <= 660s", delta)
	}
	if delta := exp - iat; delta <= 0 {
		t.Errorf("JWT exp must be after iat")
	}

	// Second call within validity — cache hit, no extra POST.
	tok2, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (second): %v", err)
	}
	if tok2 != "ghs_testtoken" {
		t.Errorf("Token (second) = %q; want %q", tok2, "ghs_testtoken")
	}
	if calls.Load() != 1 {
		t.Errorf("calls after second Token() = %d; want 1 (cache hit)", calls.Load())
	}
}

// TestGitHubAppProvider_RefreshesAfterExpiry verifies that Token() re-POSTs
// once the cached token has passed the refresh buffer.
func TestGitHubAppProvider_RefreshesAfterExpiry(t *testing.T) {
	const appID int64 = 1
	const installID int64 = 2

	// Expiry in the past → every call must refresh.
	expiry := time.Now().Add(-time.Second)
	_, auths, calls := fakeInstallationServer(t, "ghs_fresh", expiry)
	// We need to replace the server between calls so we can change the expiry.
	// Instead, use two separate servers: first returns stale, second returns valid.

	// Use a single server but with an expiry far in the future for the second response.
	var callIdx atomic.Int64
	responses := []struct {
		tok string
		exp time.Time
	}{
		{"ghs_first", time.Now().Add(-time.Second)}, // already expired
		{"ghs_second", time.Now().Add(time.Hour)},   // valid
	}
	_ = auths // from original fakeInstallationServer — not used here
	_ = calls

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(callIdx.Add(1)) - 1
		if i >= len(responses) {
			i = len(responses) - 1
		}
		resp := responses[i]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      resp.tok,
			"expires_at": resp.exp.UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(appID, installID, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	tok1, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (first): %v", err)
	}
	if tok1 != "ghs_first" {
		t.Errorf("Token (first) = %q; want ghs_first", tok1)
	}

	// First token is already expired, so next call must re-POST.
	tok2, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (second): %v", err)
	}
	if tok2 != "ghs_second" {
		t.Errorf("Token (second) = %q; want ghs_second", tok2)
	}
	if callIdx.Load() != 2 {
		t.Errorf("server was called %d times; want 2 (once for each expired token)", callIdx.Load())
	}
}

// TestGitHubAppProvider_CacheWithinBuffer verifies that a token with >60s
// remaining is returned from cache without a new POST.
func TestGitHubAppProvider_CacheWithinBuffer(t *testing.T) {
	const appID int64 = 10
	const installID int64 = 20

	// Expiry more than 60 seconds in the future — should be cached.
	expiry := time.Now().Add(2 * time.Minute)
	srv, _, calls := fakeInstallationServer(t, "ghs_cached", expiry)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(appID, installID, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	for i := range 5 {
		tok, err := p.Token(context.Background())
		if err != nil {
			t.Fatalf("Token(%d): %v", i, err)
		}
		if tok != "ghs_cached" {
			t.Errorf("Token(%d) = %q; want ghs_cached", i, tok)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("server called %d times; want 1", calls.Load())
	}
}

// TestGitHubAppProvider_BadPEM verifies that a non-PEM file is rejected at
// construction time.
func TestGitHubAppProvider_BadPEM(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(keyFile, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error for bad PEM, got nil")
	}
}

// TestGitHubAppProvider_WrongMode verifies that a key file with mode != 0400
// is rejected.
func TestGitHubAppProvider_WrongMode(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error for mode 0644, got nil")
	}
	if !strings.Contains(err.Error(), "0400") {
		t.Errorf("error %q should mention 0400", err.Error())
	}
}

// TestGitHubAppProvider_MissingFile verifies that a non-existent key file path
// returns an error.
func TestGitHubAppProvider_MissingFile(t *testing.T) {
	_, err := auth.NewGitHubAppProvider(1, 2, "/nonexistent/key.pem", "http://x")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestGitHubAppProvider_Non201Response verifies that a non-201/200 response
// from the GitHub API is treated as an error.
func TestGitHubAppProvider_Non201Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q should mention status 401", err.Error())
	}
}

// TestGitHubAppProvider_MalformedJSON verifies that malformed JSON in the
// installation token response is treated as an error.
func TestGitHubAppProvider_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{not valid json"))
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestGitHubAppProvider_EmptyToken verifies that a response with an empty token
// field is rejected.
func TestGitHubAppProvider_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "",
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for empty token field, got nil")
	}
}

// TestGitHubAppProvider_BadExpiresAt verifies that an unparseable expires_at
// returns an error.
func TestGitHubAppProvider_BadExpiresAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_tok",
			"expires_at": "not-a-time",
		})
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for bad expires_at, got nil")
	}
}

// TestGitHubAppProvider_PKCS8Key verifies that a PKCS#8-encoded RSA private key
// is accepted.
func TestGitHubAppProvider_PKCS8Key(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	expiry := time.Now().Add(time.Hour)
	srv, _, _ := fakeInstallationServer(t, "ghs_pkcs8", expiry)

	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider with PKCS8 key: %v", err)
	}
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "ghs_pkcs8" {
		t.Errorf("Token() = %q; want ghs_pkcs8", tok)
	}
}

// TestGitHubAppProvider_UnsupportedPEMType verifies that an unsupported PEM
// block type (e.g. EC PRIVATE KEY) is rejected with a clear error.
func TestGitHubAppProvider_UnsupportedPEMType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("dummy")})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ec.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error for unsupported PEM type, got nil")
	}
	if !strings.Contains(err.Error(), "EC PRIVATE KEY") {
		t.Errorf("error %q should mention the PEM block type", err.Error())
	}
}

// TestGitHubAppProvider_ServerError verifies that a network error from the
// token endpoint propagates correctly.
func TestGitHubAppProvider_ServerError(t *testing.T) {
	// Use a server that closes immediately, simulating a connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hijack and close — the client will see a connection reset.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", 500)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for server connection reset, got nil")
	}
}

// TestGitHubAppProvider_200OKAlsoAccepted verifies that HTTP 200 (not just 201)
// is accepted as a success response (some GitHub Enterprise versions return 200).
func TestGitHubAppProvider_200OKAlsoAccepted(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_200ok",
			"expires_at": expiry.UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "ghs_200ok" {
		t.Errorf("Token() = %q; want ghs_200ok", tok)
	}
}

// TestGitHubAppProvider_ReadFileError covers the os.ReadFile error branch in
// NewGitHubAppProvider by injecting a failing read after a successful Stat.
func TestGitHubAppProvider_ReadFileError(t *testing.T) {
	_, keyFile := generateTestKey(t)

	orig := *auth.AppReadFile
	*auth.AppReadFile = func(string) ([]byte, error) {
		return nil, errors.New("injected read error")
	}
	t.Cleanup(func() { *auth.AppReadFile = orig })

	_, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error from injected ReadFile failure, got nil")
	}
}

// TestGitHubAppProvider_InvalidPKCS8DER verifies that a "PRIVATE KEY" PEM block
// with corrupted DER content returns an error from ParsePKCS8PrivateKey.
func TestGitHubAppProvider_InvalidPKCS8DER(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-valid-der")})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bad_pkcs8.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error for invalid PKCS8 DER, got nil")
	}
}

// TestGitHubAppProvider_PKCS8NotRSA verifies that a PKCS8 PEM block containing
// a non-RSA key (EC P256) is rejected with "PKCS8 key is not RSA".
func TestGitHubAppProvider_PKCS8NotRSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ec_pkcs8.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, err = auth.NewGitHubAppProvider(1, 2, keyFile, "http://x")
	if err == nil {
		t.Fatal("expected error for EC PKCS8 key, got nil")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error %q should mention 'not RSA'", err.Error())
	}
}

// TestGitHubAppProvider_RSASignerError covers the rsa.SignPKCS1v15 error branch
// in mintJWT by injecting a failing signer.
func TestGitHubAppProvider_RSASignerError(t *testing.T) {
	_, keyFile := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Should never be reached; signer fails before any HTTP call.
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	orig := *auth.RSASigner
	*auth.RSASigner = func(_ *rsa.PrivateKey, _ []byte) ([]byte, error) {
		return nil, errors.New("injected signer error")
	}
	t.Cleanup(func() { *auth.RSASigner = orig })

	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from injected signer failure, got nil")
	}
}

// TestGitHubAppProvider_BadRequestURL covers the http.NewRequestWithContext
// error branch in requestInstallationToken by injecting a failing request builder.
func TestGitHubAppProvider_BadRequestURL(t *testing.T) {
	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, "http://valid-at-init")
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}

	// Inject an appNewRequest that always fails.
	orig := *auth.AppNewRequest
	*auth.AppNewRequest = func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
		return nil, errors.New("injected request error")
	}
	t.Cleanup(func() { *auth.AppNewRequest = orig })

	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from injected request failure, got nil")
	}
}

// TestGitHubAppProvider_BodyReadError covers the io.ReadAll error branch in
// requestInstallationToken by hijacking the connection and truncating the response.
func TestGitHubAppProvider_BodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		// Advertise a 5000-byte body but write nothing, then close.
		_, _ = bufrw.WriteString("HTTP/1.1 201 Created\r\nContent-Length: 5000\r\nContent-Type: application/json\r\n\r\n")
		_, _ = bufrw.WriteString("truncated")
		_ = bufrw.Flush()
		conn.Close()
	}))
	t.Cleanup(srv.Close)

	_, keyFile := generateTestKey(t)
	p, err := auth.NewGitHubAppProvider(1, 2, keyFile, srv.URL)
	if err != nil {
		t.Fatalf("NewGitHubAppProvider: %v", err)
	}
	_, err = p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error from body read failure, got nil")
	}
}
