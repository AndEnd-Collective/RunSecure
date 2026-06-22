package imageallow

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// errReader is a minimal io.Reader that returns a fixed error after
// delivering an initial prefix, allowing us to drive the scanner.Err() path.
type errReader struct {
	prefix []byte
	offset int
	rerr   error
}

func (e *errReader) Read(p []byte) (int, error) {
	remaining := len(e.prefix) - e.offset
	if remaining > 0 {
		n := copy(p, e.prefix[e.offset:])
		e.offset += n
		return n, nil
	}
	return 0, e.rerr
}

func TestLoad_ParsesDigestEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowed.txt")
	require.NoError(t, os.WriteFile(path, []byte(`
# Allowed runsecure images, one digest reference per line.
ghcr.io/andend-collective/runsecure/runner-node@sha256:aaaa
ghcr.io/andend-collective/runsecure/runner-python@sha256:bbbb

# Blank lines and # comments ignored.
ghcr.io/andend-collective/runsecure/proxy@sha256:cccc
`), 0o644))

	a, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, 3, a.Size())

	require.True(t, a.Allows("ghcr.io/andend-collective/runsecure/runner-node@sha256:aaaa"))
	require.True(t, a.Allows("ghcr.io/andend-collective/runsecure/proxy@sha256:cccc"))
	require.False(t, a.Allows("ghcr.io/andend-collective/runsecure/runner-node:latest"))
	require.False(t, a.Allows("ghcr.io/andend-collective/runsecure/runner-node@sha256:other"))
}

func TestLoad_RejectsTagOnlyEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowed.txt")
	require.NoError(t, os.WriteFile(path, []byte("ghcr.io/foo:latest\n"), 0o644))
	_, err := Load(path)
	require.ErrorContains(t, err, "@sha256:")
}

// Mutation kill: imageallow.go:33 — `lineNo++`. The bad-line line number
// must appear correctly in the error. Mutating to `lineNo--` would
// produce ":-1:" or similar; mutating to no-op would always report ":0:".
func TestLoad_ErrorReportsCorrectLineNumber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowed.txt")
	contents := []byte(
		"# header comment\n" +
			"ghcr.io/ok@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
			"\n" +
			"ghcr.io/bad:latest\n",
	)
	require.NoError(t, os.WriteFile(path, contents, 0o644))
	_, err := Load(path)
	require.ErrorContains(t, err, ":4:",
		"bad entry is on line 4; lineNo must increment per scanned line")
}

func TestLoad_MissingFileErrors(t *testing.T) {
	_, err := Load("/nonexistent/path")
	require.Error(t, err)
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("# only a comment\n\n"), 0o644))
	a, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, 0, a.Size())
}

// TestParse_ScannerError drives the scanner.Err() branch that is unreachable
// through a real file but reachable via a reader that returns a mid-stream
// I/O error. The error must propagate wrapped under "imageallow: read".
func TestParse_ScannerError(t *testing.T) {
	ioErr := errors.New("simulated read error")
	// Deliver one valid digest line then fail on the next Read call so that
	// scanner.Scan() returns false with a non-nil Err().
	r := &errReader{
		prefix: []byte("ghcr.io/ok@sha256:aabbcc\n"),
		rerr:   ioErr,
	}
	_, err := parse(r, "fake-label")
	require.Error(t, err)
	require.ErrorContains(t, err, "imageallow: read fake-label")
	require.ErrorIs(t, err, ioErr)
}

// TestParse_AllowsAndDenies verifies parse with a valid in-memory reader —
// confirms the reader-based path is functionally equivalent to Load.
func TestParse_AllowsAndDenies(t *testing.T) {
	content := "# comment\nghcr.io/img@sha256:deadbeef\n\nghcr.io/other@sha256:cafebabe\n"
	r := &errReader{prefix: []byte(content), rerr: io.EOF}
	a, err := parse(r, "mem")
	require.NoError(t, err)
	require.Equal(t, 2, a.Size())
	require.True(t, a.Allows("ghcr.io/img@sha256:deadbeef"))
	require.False(t, a.Allows("ghcr.io/img:latest"))
}

// ─── LoadWithExtra tests (issue #54 fix 3) ────────────────────────────────────

// TestLoadWithExtra_MergesBothFiles verifies that entries from both the base
// and extra files are present in the merged allowlist.
func TestLoadWithExtra_MergesBothFiles(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.txt")
	extraPath := filepath.Join(dir, "extra.txt")

	require.NoError(t, os.WriteFile(basePath, []byte(
		"ghcr.io/runsecure/proxy@sha256:aabbcc\n"+
			"ghcr.io/runsecure/runner-node@sha256:ddeeff\n",
	), 0o644))
	require.NoError(t, os.WriteFile(extraPath, []byte(
		"# release-specific digests\n"+
			"ghcr.io/runsecure/proxy@sha256:112233\n",
	), 0o644))

	a, err := LoadWithExtra(basePath, extraPath)
	require.NoError(t, err)
	require.Equal(t, 3, a.Size())
	require.True(t, a.Allows("ghcr.io/runsecure/proxy@sha256:aabbcc"))
	require.True(t, a.Allows("ghcr.io/runsecure/runner-node@sha256:ddeeff"))
	require.True(t, a.Allows("ghcr.io/runsecure/proxy@sha256:112233"))
}

// TestLoadWithExtra_EmptyExtraPath_ReturnsBase verifies that an empty extraPath
// behaves identically to Load (no merge attempt, no error).
func TestLoadWithExtra_EmptyExtraPath_ReturnsBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.txt")
	require.NoError(t, os.WriteFile(basePath, []byte(
		"ghcr.io/runsecure/proxy@sha256:aabbcc\n",
	), 0o644))

	a, err := LoadWithExtra(basePath, "")
	require.NoError(t, err)
	require.Equal(t, 1, a.Size())
	require.True(t, a.Allows("ghcr.io/runsecure/proxy@sha256:aabbcc"))
}

// TestLoadWithExtra_MissingExtraFile_NotAnError verifies that when extraPath is
// set but the file does not exist, LoadWithExtra succeeds with only the base
// entries. Operators may set RUNSECURE_ALLOWED_IMAGES_EXTRA_FILE before the
// file is created; the socket-proxy must still start.
func TestLoadWithExtra_MissingExtraFile_NotAnError(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.txt")
	require.NoError(t, os.WriteFile(basePath, []byte(
		"ghcr.io/runsecure/proxy@sha256:aabbcc\n",
	), 0o644))

	a, err := LoadWithExtra(basePath, filepath.Join(dir, "nonexistent.txt"))
	require.NoError(t, err)
	require.Equal(t, 1, a.Size())
}

// TestLoadWithExtra_ExtraFileHasTagEntry_Errors verifies that a tag-only entry
// in the extra file is rejected (same format requirement as the base file).
func TestLoadWithExtra_ExtraFileHasTagEntry_Errors(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.txt")
	extraPath := filepath.Join(dir, "extra.txt")
	require.NoError(t, os.WriteFile(basePath, []byte(
		"ghcr.io/runsecure/proxy@sha256:aabbcc\n",
	), 0o644))
	require.NoError(t, os.WriteFile(extraPath, []byte(
		"ghcr.io/runsecure/proxy:latest\n",
	), 0o644))

	_, err := LoadWithExtra(basePath, extraPath)
	require.ErrorContains(t, err, "@sha256:")
}

// TestLoadWithExtra_BaseFileMissing_Errors verifies that an error loading the
// base allowlist propagates (extra file is irrelevant when base fails).
func TestLoadWithExtra_BaseFileMissing_Errors(t *testing.T) {
	_, err := LoadWithExtra("/nonexistent/base.txt", "")
	require.Error(t, err)
}

// TestLoadWithExtra_ExtraFileUnreadable_Errors covers the branch in LoadWithExtra
// where os.Open(extraPath) fails with a non-IsNotExist error (e.g. permission denied).
// Without this test, the "imageallow: open extra %s" error message is unreachable.
func TestLoadWithExtra_ExtraFileUnreadable_Errors(t *testing.T) {
	if os.Getuid() == 0 {
		// Root bypasses permission checks; skip rather than create a fragile workaround.
		t.Skip("cannot test permission denied as root")
	}
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.txt")
	extraPath := filepath.Join(dir, "extra.txt")
	require.NoError(t, os.WriteFile(basePath, []byte(
		"ghcr.io/runsecure/proxy@sha256:aabbcc\n",
	), 0o644))
	// Create the extra file then chmod 000 so it exists but is unreadable.
	require.NoError(t, os.WriteFile(extraPath, []byte(""), 0o000))
	defer os.Chmod(extraPath, 0o644) // restore so TempDir cleanup can remove it

	_, err := LoadWithExtra(basePath, extraPath)
	require.ErrorContains(t, err, "imageallow: open extra")
}
