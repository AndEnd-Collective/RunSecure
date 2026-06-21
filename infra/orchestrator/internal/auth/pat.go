package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// osReadFile is the file-read function used by NewPATProvider. It is a
// package-level variable so that export_test.go can swap it in tests to
// exercise the ReadFile error branch without OS-level trickery.
var osReadFile = os.ReadFile

// patProvider implements Provider using a fine-grained Personal Access Token
// stored in a file.
//
// Read-behavior: the token is read once at construction (NewPATProvider) and
// cached for the lifetime of the provider. This mirrors the initial load in
// github.Client.reload() and keeps Token() allocation-free on the hot path.
// Unlike github.Client — which also watches mtime and reloads on rotation —
// patProvider intentionally omits hot-reload: the Provider interface is meant
// to be the single credential source and a restart is an acceptable rotation
// strategy for the orchestrator process. If hot-reload is needed, wrap with a
// rotating decorator rather than bloating this type.
type patProvider struct {
	token string
}

// NewPATProvider constructs a patProvider from the given file path.
// The file must exist and have mode exactly 0400; any other mode is rejected
// to prevent accidental credential exposure (mirrors the check in
// internal/config/scope_validate.go:37).
func NewPATProvider(patFile string) (Provider, error) {
	info, err := os.Stat(patFile)
	if err != nil {
		return nil, fmt.Errorf("auth: stat pat file %s: %w", patFile, err)
	}
	if info.Mode().Perm() != 0o400 {
		return nil, fmt.Errorf("auth: pat file %s must be mode 0400 (got %o)", patFile, info.Mode().Perm())
	}
	b, err := osReadFile(patFile)
	if err != nil {
		return nil, fmt.Errorf("auth: read pat file %s: %w", patFile, err)
	}
	return &patProvider{token: strings.TrimSpace(string(b))}, nil
}

// Token returns the cached PAT. ctx is accepted for interface compliance and
// future cancellation support.
func (p *patProvider) Token(_ context.Context) (string, error) {
	return p.token, nil
}
