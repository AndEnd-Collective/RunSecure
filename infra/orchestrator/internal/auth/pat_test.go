package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/auth"
)

func writeTokenFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return p
}

// TestPATProvider_TokenTrimmed verifies that whitespace is stripped from the
// token read at construction time.
func TestPATProvider_TokenTrimmed(t *testing.T) {
	p := writeTokenFile(t, " tok \n", 0o400)

	prov, err := auth.NewPATProvider(p)
	if err != nil {
		t.Fatalf("NewPATProvider: unexpected error: %v", err)
	}

	got, err := prov.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: unexpected error: %v", err)
	}
	if got != "tok" {
		t.Errorf("Token() = %q; want %q", got, "tok")
	}
}

// TestPATProvider_RejectsWrongMode verifies that a file with mode 0444
// (readable by group/other) is rejected at construction with an error
// that mentions "0400".
func TestPATProvider_RejectsWrongMode(t *testing.T) {
	p := writeTokenFile(t, "secret", 0o444)

	_, err := auth.NewPATProvider(p)
	if err == nil {
		t.Fatal("NewPATProvider: expected error for mode 0444, got nil")
	}
	if !strings.Contains(err.Error(), "0400") {
		t.Errorf("error %q should mention 0400", err.Error())
	}
}

// TestPATProvider_MissingFile verifies that a non-existent file path returns
// an error at construction time.
func TestPATProvider_MissingFile(t *testing.T) {
	_, err := auth.NewPATProvider("/nonexistent/path/to/token")
	if err == nil {
		t.Fatal("NewPATProvider: expected error for missing file, got nil")
	}
}

// TestPATProvider_ReadError exercises the os.ReadFile error branch by
// injecting a stub that fails after Stat succeeds. This branch is unreachable
// via normal filesystem operations (a 0400-mode file readable by owner won't
// fail ReadFile after a successful Stat) but must be covered because any I/O
// path is a security-critical failure mode.
func TestPATProvider_ReadError(t *testing.T) {
	p := writeTokenFile(t, "secret", 0o400)

	// Swap the internal reader for one that always fails.
	orig := *auth.ReadFile
	*auth.ReadFile = func(string) ([]byte, error) {
		return nil, errors.New("injected I/O error")
	}
	t.Cleanup(func() { *auth.ReadFile = orig })

	_, err := auth.NewPATProvider(p)
	if err == nil {
		t.Fatal("NewPATProvider: expected error from ReadFile injection, got nil")
	}
}

// TestPATProvider_MtimeReload verifies that Token() reloads the file from disk
// when its mtime changes, returning the new token value without a provider
// restart.
func TestPATProvider_MtimeReload(t *testing.T) {
	p := writeTokenFile(t, "v1token", 0o400)

	prov, err := auth.NewPATProvider(p)
	if err != nil {
		t.Fatalf("NewPATProvider: %v", err)
	}

	tok1, err := prov.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (v1): %v", err)
	}
	if tok1 != "v1token" {
		t.Errorf("Token (v1) = %q; want v1token", tok1)
	}

	// Rotate the PAT: chmod to allow write, rewrite, chmod back, advance mtime.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("Chmod 0600: %v", err)
	}
	if err := os.WriteFile(p, []byte("v2token"), 0o600); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatalf("Chmod 0400: %v", err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	tok2, err := prov.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (v2): %v", err)
	}
	if tok2 != "v2token" {
		t.Errorf("Token (v2) = %q; want v2token", tok2)
	}
}

// TestPATProvider_NoReloadWhenUnchanged verifies that Token() does NOT re-read
// the file when the mtime is the same (the stat check must short-circuit).
func TestPATProvider_NoReloadWhenUnchanged(t *testing.T) {
	p := writeTokenFile(t, "stable", 0o400)

	// Inject a counting ReadFile; count > 1 means an extra reload happened.
	var readCount int
	orig := *auth.ReadFile
	*auth.ReadFile = func(name string) ([]byte, error) {
		readCount++
		return orig(name)
	}
	t.Cleanup(func() { *auth.ReadFile = orig })

	prov, err := auth.NewPATProvider(p)
	if err != nil {
		t.Fatalf("NewPATProvider: %v", err)
	}
	// readCount == 1 (construction read)

	for range 10 {
		if _, err := prov.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	// Mtime hasn't changed, so no reload should have occurred.
	if readCount != 1 {
		t.Errorf("ReadFile called %d times; want exactly 1 (no reload when mtime unchanged)", readCount)
	}
}

// TestPATProvider_Token_StatError verifies that a stat failure inside Token()
// is propagated as an error.
func TestPATProvider_Token_StatError(t *testing.T) {
	p := writeTokenFile(t, "secret", 0o400)

	prov, err := auth.NewPATProvider(p)
	if err != nil {
		t.Fatalf("NewPATProvider: %v", err)
	}

	// Inject a failing stat.
	orig := *auth.StatFile
	*auth.StatFile = func(string) (os.FileInfo, error) {
		return nil, errors.New("injected stat error")
	}
	t.Cleanup(func() { *auth.StatFile = orig })

	_, err = prov.Token(context.Background())
	if err == nil {
		t.Fatal("Token: expected error from stat injection, got nil")
	}
}

// TestPATProvider_Token_ReloadReadError verifies that a ReadFile failure during
// mtime-triggered reload is propagated as an error.
func TestPATProvider_Token_ReloadReadError(t *testing.T) {
	p := writeTokenFile(t, "secret", 0o400)

	prov, err := auth.NewPATProvider(p)
	if err != nil {
		t.Fatalf("NewPATProvider: %v", err)
	}

	// Advance mtime so Token() decides to reload.
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// Inject a failing ReadFile so the reload fails.
	orig := *auth.ReadFile
	*auth.ReadFile = func(string) ([]byte, error) {
		return nil, errors.New("injected read error")
	}
	t.Cleanup(func() { *auth.ReadFile = orig })

	_, err = prov.Token(context.Background())
	if err == nil {
		t.Fatal("Token: expected error from reload ReadFile injection, got nil")
	}
}
