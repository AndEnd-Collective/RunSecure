package egress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/stretchr/testify/require"
)

func TestRender_HappyPath(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{
		Egress: runneryml.Egress{AllowDomains: []string{"api.github.com", "registry.npmjs.org"}},
	}
	cfgDir, err := g.Render("spawn-1", r, security.Defaults("strict"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "spawn-1"), cfgDir)

	squid, err := os.ReadFile(filepath.Join(cfgDir, "squid.conf"))
	require.NoError(t, err)
	require.Contains(t, string(squid), ".api.github.com")
	require.Contains(t, string(squid), ".registry.npmjs.org")
	require.Contains(t, string(squid), "http_access deny all")

	dns, err := os.ReadFile(filepath.Join(cfgDir, "dnsmasq.conf"))
	require.NoError(t, err)
	require.Contains(t, string(dns), "no-resolv")
	require.Contains(t, string(dns), "local=/./")

	ha, err := os.ReadFile(filepath.Join(cfgDir, "haproxy.cfg"))
	require.NoError(t, err)
	require.Contains(t, string(ha), "mode tcp")
}

func TestRender_WildcardEntries_StrictDenied(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("strict") // AllowWildcards=false
	policy.WildcardEntries = []string{"*.amazonaws.com"}

	cfgDir, err := g.Render("spawn-2", r, policy)
	require.NoError(t, err)
	squid, _ := os.ReadFile(filepath.Join(cfgDir, "squid.conf"))
	require.NotContains(t, string(squid), "amazonaws.com")
}

func TestRender_WildcardEntries_PermitWhenAllowed(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard") // AllowWildcards=true
	policy.WildcardEntries = []string{"*.amazonaws.com"}

	cfgDir, err := g.Render("spawn-3", r, policy)
	require.NoError(t, err)
	squid, _ := os.ReadFile(filepath.Join(cfgDir, "squid.conf"))
	require.Contains(t, string(squid), ".amazonaws.com")

	dns, _ := os.ReadFile(filepath.Join(cfgDir, "dnsmasq.conf"))
	require.Contains(t, string(dns), "server=/amazonaws.com/")
}

func TestRender_MkdirFails_Errors(t *testing.T) {
	// BaseDir under a file (not a dir) — mkdir must fail.
	dir := t.TempDir()
	collidingFile := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(collidingFile, []byte("x"), 0o644))
	g := NewFSGenerator(collidingFile)
	_, err := g.Render("s", &runneryml.Runner{}, security.Defaults("strict"))
	require.Error(t, err)
}

// TestRender_WriteFails_Errors verifies that a write failure on any of the
// three config files surfaces as an error. We force the failure by making
// the per-spawn directory read-only after mkdir but before the writes.
func TestRender_WriteFails_Errors(t *testing.T) {
	dir := t.TempDir()
	// Make the base dir read-only AFTER one successful Render call so the
	// second one tries to write into a non-writable existing dir.
	g := NewFSGenerator(dir)

	// Pre-create the spawn dir as read-only.
	spawnDir := filepath.Join(dir, "ro-spawn")
	require.NoError(t, os.MkdirAll(spawnDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(spawnDir, 0o755) })

	_, err := g.Render("ro-spawn", &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"x.com"}}}, security.Defaults("strict"))
	require.Error(t, err)
}
