package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// githubAppProvider implements Provider using GitHub App installation tokens.
// It builds a short-lived JWT signed with the App's RSA private key, exchanges
// it for an installation access token via the GitHub API, and caches that token
// until within 60 s of its expiry.
//
// Thread-safe via mu. Never logs the private key or any token value.
type githubAppProvider struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	apiBaseURL     string
	hc             *http.Client

	mu        sync.Mutex
	cachedTok string
	expiresAt time.Time
}

// tokenRefreshBuffer is how far in advance of the token's expiry we treat it
// as expired and refresh it.
const tokenRefreshBuffer = 60 * time.Second

// jwtClockSkewBuffer is subtracted from iat to account for clock drift between
// orchestrator and GitHub's servers.
const jwtClockSkewBuffer = 60 * time.Second

// jwtMaxAge is the maximum allowed lifetime for a GitHub App JWT.
const jwtMaxAge = 10 * time.Minute

// appReadFile is the file-read function used by NewGitHubAppProvider. It is a
// package-level variable so that tests can inject failures after a successful
// Stat.
var appReadFile = os.ReadFile

// NewGitHubAppProvider constructs a Provider that authenticates as a GitHub App
// installation. privateKeyPEMFile must exist and have mode exactly 0400.
//
// Parameters:
//
//	appID          — the GitHub App's numeric ID (iss claim in JWTs)
//	installationID — the numeric installation ID to mint tokens for
//	privateKeyPEMFile — path to the PEM-encoded RSA private key (mode 0400)
//	apiBaseURL     — GitHub API base URL (e.g. "https://api.github.com")
func NewGitHubAppProvider(appID, installationID int64, privateKeyPEMFile, apiBaseURL string) (Provider, error) {
	info, err := os.Stat(privateKeyPEMFile)
	if err != nil {
		return nil, fmt.Errorf("auth: stat private key file %s: %w", privateKeyPEMFile, err)
	}
	if info.Mode().Perm() != 0o400 {
		return nil, fmt.Errorf("auth: private key file %s must be mode 0400 (got %o)", privateKeyPEMFile, info.Mode().Perm())
	}
	pemBytes, err := appReadFile(privateKeyPEMFile)
	if err != nil {
		return nil, fmt.Errorf("auth: read private key file %s: %w", privateKeyPEMFile, err)
	}
	key, err := parseRSAPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse private key from %s: %w", privateKeyPEMFile, err)
	}
	return &githubAppProvider{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		apiBaseURL:     strings.TrimRight(apiBaseURL, "/"),
		hc:             &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// parseRSAPrivateKey decodes a PEM block and parses an RSA private key from
// PKCS#1 (RSAPrivateKey) or PKCS#8 (PrivateKeyInfo) encoding.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q (want RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}

// Token returns a valid installation access token, refreshing it when it is
// within tokenRefreshBuffer of expiry. Thread-safe.
func (g *githubAppProvider) Token(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.cachedTok != "" && time.Until(g.expiresAt) > tokenRefreshBuffer {
		return g.cachedTok, nil
	}

	jwt, err := g.mintJWT()
	if err != nil {
		return "", fmt.Errorf("auth: mint GitHub App JWT: %w", err)
	}

	tok, exp, err := g.requestInstallationToken(ctx, jwt)
	if err != nil {
		return "", err
	}

	g.cachedTok = tok
	g.expiresAt = exp
	return tok, nil
}

// rsaSigner is the signing function used by mintJWT. It is a package-level
// variable so tests can inject a failing signer to cover the error branch.
var rsaSigner = func(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}

// mintJWT builds and signs a GitHub App JWT using RS256.
// JWT structure: base64url(header) + "." + base64url(claims) + "." + base64url(sig).
// No third-party JWT library is used — the construction is two JSON objects and
// one RSA-SHA256 signature, well within stdlib's capability.
//
// json.Marshal is called on plain string/int maps whose types can never trigger
// an encoding error; the only real error path is rsa.SignPKCS1v15.
func (g *githubAppProvider) mintJWT() (string, error) {
	now := time.Now()
	iat := now.Add(-jwtClockSkewBuffer).Unix()
	exp := now.Add(jwtMaxAge).Unix()

	// json.Marshal on map[string]string and map[string]any with int64/string
	// values cannot fail; errors are not checked to avoid dead-code branches.
	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	})
	claimsJSON, _ := json.Marshal(map[string]any{
		"iat": iat,
		"exp": exp,
		"iss": g.appID,
	})

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, err := rsaSigner(g.privateKey, digest)
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// installationTokenResponse is the JSON body returned by the GitHub API when
// creating an installation access token.
type installationTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"` // RFC3339
}

// appNewRequest is the http.NewRequestWithContext function used by
// requestInstallationToken. Package-level variable for test injection.
var appNewRequest = http.NewRequestWithContext

// requestInstallationToken POSTs to the GitHub API to obtain an installation
// access token, returning the token string and its expiry time.
func (g *githubAppProvider) requestInstallationToken(ctx context.Context, jwt string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", g.apiBaseURL, g.installationID)
	req, err := appNewRequest(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: build installation token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.hc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: POST installation token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: read installation token response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("auth: GitHub App token endpoint returned %d", resp.StatusCode)
	}

	var result installationTokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: parse installation token response: %w", err)
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("auth: installation token response missing 'token' field")
	}

	exp, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: parse installation token expires_at %q: %w", result.ExpiresAt, err)
	}

	return result.Token, exp, nil
}
