// export_test.go exposes internal hooks for white-box testing.
// This file is compiled only during `go test`.
package auth

import "net/http"

// ReadFile allows tests to inject a failing ReadFile implementation so the
// os.ReadFile error branch in NewPATProvider can be exercised without OS-level
// tricks (e.g. root-owned files or kernel mocks).
var ReadFile = &osReadFile

// StatFile allows tests to inject a failing os.Stat implementation so the
// stat error branch in patProvider.Token() can be exercised.
var StatFile = &osStat

// AppReadFile allows tests to inject a failing ReadFile for NewGitHubAppProvider.
var AppReadFile = &appReadFile

// RSASigner allows tests to inject a failing RSA signer to cover the
// rsa.SignPKCS1v15 error branch in mintJWT.
var RSASigner = &rsaSigner

// AppNewRequest allows tests to inject a failing http.NewRequestWithContext
// function to cover the error branch in requestInstallationToken.
var AppNewRequest = &appNewRequest

// SetProviderHTTPClient replaces the HTTP client on a githubAppProvider.
// Returns a restore function that resets it to the original.
func SetProviderHTTPClient(p Provider, hc *http.Client) func() {
	g := p.(*githubAppProvider)
	orig := g.hc
	g.hc = hc
	return func() { g.hc = orig }
}
