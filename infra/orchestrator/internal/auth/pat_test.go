package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
