package cornerstone

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignatures_AllConstantsHaveRegistryFiles asserts that every event-name
// constant in this package has a matching .cornerstone/events/<name>.yaml
// file. Prevents drift between code and registry.
func TestSignatures_AllConstantsHaveRegistryFiles(t *testing.T) {
	root := repoRoot(t)
	for _, name := range AllEventNames() {
		path := filepath.Join(root, ".cornerstone", "events", name+".yaml")
		_, err := os.Stat(path)
		require.NoError(t, err, "missing registry file for event %s at %s", name, path)
	}
}

func TestProjectSignature_IsStableConstant(t *testing.T) {
	require.Equal(t, "runsecure-orchestrator-v1", ProjectSignature)
}

func TestAllEventNames_CountMatchesConstantCount(t *testing.T) {
	// Sanity guard against accidentally adding a constant without listing it.
	require.Len(t, AllEventNames(), 18)
}

// repoRoot walks up from the test file until it finds a .git directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	for cur := wd; cur != "/"; cur = filepath.Dir(cur) {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return cur
		}
	}
	t.Fatal("could not find repo root")
	return ""
}
