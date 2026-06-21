package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// osReadFile is the file-read function used by NewPATProvider. It is a
// package-level variable so that export_test.go can swap it in tests to
// exercise the ReadFile error branch without OS-level trickery.
var osReadFile = os.ReadFile

// osStat is the file-stat function used by patProvider for mtime checks.
// Package-level variable so tests can inject failures.
var osStat = os.Stat

// patProvider implements Provider using a fine-grained Personal Access Token
// stored in a file.
//
// Read-behavior: the token is read once at construction (NewPATProvider) and
// cached. On each Token() call the file mtime is checked; if it has changed
// the file is re-read (hot-reload without orchestrator restart). This matches
// the mtime-reload behavior that github.Client previously implemented directly.
// Thread-safe via mu.
type patProvider struct {
	patFile string
	mu      sync.RWMutex
	token   string
	mtime   time.Time
}

// NewPATProvider constructs a patProvider from the given file path.
// The file must exist and have mode exactly 0400; any other mode is rejected
// to prevent accidental credential exposure.
func NewPATProvider(patFile string) (Provider, error) {
	info, err := osStat(patFile)
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
	return &patProvider{
		patFile: patFile,
		token:   strings.TrimSpace(string(b)),
		mtime:   info.ModTime(),
	}, nil
}

// Token returns the current PAT, reloading from disk when the file mtime has
// changed. ctx is accepted for interface compliance and future cancellation.
func (p *patProvider) Token(_ context.Context) (string, error) {
	info, err := osStat(p.patFile)
	if err != nil {
		return "", fmt.Errorf("auth: stat pat file %s: %w", p.patFile, err)
	}

	p.mu.RLock()
	stale := !info.ModTime().Equal(p.mtime)
	p.mu.RUnlock()

	if stale {
		if err := p.reload(info); err != nil {
			return "", err
		}
	}

	p.mu.RLock()
	tok := p.token
	p.mu.RUnlock()
	return tok, nil
}

// reload re-reads the PAT file and updates the cached token and mtime.
func (p *patProvider) reload(info os.FileInfo) error {
	b, err := osReadFile(p.patFile)
	if err != nil {
		return fmt.Errorf("auth: read pat file %s: %w", p.patFile, err)
	}
	p.mu.Lock()
	p.token = strings.TrimSpace(string(b))
	p.mtime = info.ModTime()
	p.mu.Unlock()
	return nil
}
