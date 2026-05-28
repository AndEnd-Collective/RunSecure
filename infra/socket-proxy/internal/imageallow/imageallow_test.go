package imageallow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
