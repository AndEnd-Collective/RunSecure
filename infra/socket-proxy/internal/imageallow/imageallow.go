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
	"os"
	"strings"
)

type Allowlist struct {
	allowed map[string]struct{}
}

func Load(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("imageallow: open %s: %w", path, err)
	}
	defer f.Close()

	a := &Allowlist{allowed: map[string]struct{}{}}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "@sha256:") {
			return nil, fmt.Errorf("imageallow: %s:%d: entries must use @sha256: digest form, got %q", path, lineNo, line)
		}
		a.allowed[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("imageallow: read %s: %w", path, err)
	}
	return a, nil
}

func (a *Allowlist) Allows(ref string) bool {
	_, ok := a.allowed[ref]
	return ok
}

// Size returns the number of allowed digests (for logging / health endpoints).
func (a *Allowlist) Size() int { return len(a.allowed) }
