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
