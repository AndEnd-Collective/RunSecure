// Package imageallow parses and matches an image-digest allowlist.
//
// File format: one image reference per line, in the form
//
//	<registry>/<image>@sha256:<hex>
//
// Tag-based references (image:latest) are rejected at load time.
// Lines starting with '#' and blank lines are ignored.
package imageallow

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type Allowlist struct {
	allowed map[string]struct{}
}

// Load opens path and delegates to parse. The label in error messages is the
// file path so callers can locate the offending line.
func Load(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("imageallow: open %s: %w", path, err)
	}
	defer f.Close()
	return parse(f, path)
}

// LoadWithExtra loads the primary allowlist from path, then merges entries from
// extraPath if it is non-empty and the file exists. This allows operators to
// supply release-specific digests at runtime without rebuilding the
// socket-proxy image — addressing the bootstrap problem where a newly-released
// proxy/runner image digest cannot be baked into the allowlist at release time
// because the image is not yet published when the release tag is cut (#54 fix 3).
//
// extraPath must follow the same format as path. Errors loading extraPath
// are returned; a missing file (os.IsNotExist) is silently ignored so the
// operator does not need to supply the file on every deployment.
func LoadWithExtra(path, extraPath string) (*Allowlist, error) {
	base, err := Load(path)
	if err != nil {
		return nil, err
	}
	if extraPath == "" {
		return base, nil
	}
	ef, err := os.Open(extraPath)
	if os.IsNotExist(err) {
		// Extra file absent — not an error. Operator didn't supply one.
		return base, nil
	}
	if err != nil {
		return nil, fmt.Errorf("imageallow: open extra %s: %w", extraPath, err)
	}
	defer ef.Close()
	extra, err := parse(ef, extraPath)
	if err != nil {
		return nil, err
	}
	// Merge: add all extra entries into base.
	for ref := range extra.allowed {
		base.allowed[ref] = struct{}{}
	}
	return base, nil
}

// parse scans r line-by-line, building an Allowlist. label is used in error
// messages (typically the file path). Extracted so tests can inject a reader
// that returns mid-stream I/O errors to exercise the scanner.Err() branch.
func parse(r io.Reader, label string) (*Allowlist, error) {
	a := &Allowlist{allowed: map[string]struct{}{}}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "@sha256:") {
			return nil, fmt.Errorf("imageallow: %s:%d: entries must use @sha256: digest form, got %q", label, lineNo, line)
		}
		a.allowed[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("imageallow: read %s: %w", label, err)
	}
	return a, nil
}

func (a *Allowlist) Allows(ref string) bool {
	_, ok := a.allowed[ref]
	return ok
}

// Size returns the number of allowed digests (for logging / health endpoints).
func (a *Allowlist) Size() int { return len(a.allowed) }
