package egress

import (
	"net"
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
	g := NewFSGenerator(dir)
	spawnDir := filepath.Join(dir, "ro-spawn")
	require.NoError(t, os.MkdirAll(spawnDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(spawnDir, 0o755) })

	_, err := g.Render("ro-spawn", &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"x.com"}}}, security.Defaults("strict"))
	require.Error(t, err)
}

// Covers generate.go:43 — haproxy.cfg write fails (squid.conf already written).
func TestRender_HAProxyWriteFails(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	spawnDir := filepath.Join(dir, "spawn-1")
	require.NoError(t, os.MkdirAll(spawnDir, 0o755))
	// Write squid.conf successfully; then put a directory at haproxy.cfg so
	// the WriteFile fails with "is a directory".
	require.NoError(t, os.WriteFile(filepath.Join(spawnDir, "squid.conf"), []byte("ok"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(spawnDir, "haproxy.cfg"), 0o755))

	_, err := g.Render("spawn-1", &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"x"}}}, security.Defaults("strict"))
	require.Error(t, err)
}

// Covers generate.go:46 — dnsmasq.conf write fails.
// Mutation kills for squid.go:29 — the `*.foo` suffix detection.
// The full line-shape check (with the `dstdomain ` prefix) discriminates
// "trimmed to suffix" from "preserved as literal" — a bare substring check
// would pass under either output for inputs like "*.amazonaws.com".
func TestRenderSquid_WildcardEdgeCases(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.example.com"}}}
	policy := security.Defaults("standard") // allows wildcards
	policy.WildcardEntries = []string{
		"*.amazonaws.com", // expected to be TRIMMED → "dstdomain .amazonaws.com"
		"*.",              // 2 chars exactly — must NOT be trimmed (>2 boundary)
		"foo.com",         // non-wildcard — must NOT be trimmed (w[0] != '*')
		"*foo",            // missing '.' after '*' — must NOT be trimmed (w[1] != '.')
	}
	out := string(RenderSquid(r, policy))

	// Trimmed case (original behavior): line ends with " .amazonaws.com\n"
	// — note the leading SPACE+DOT, distinguishing from "*.amazonaws.com".
	require.Contains(t, out, " .amazonaws.com\n",
		"3-char+ wildcard with .: must emit suffix-trimmed form")
	require.NotContains(t, out, " *.amazonaws.com\n",
		"3-char+ wildcard MUST be trimmed (no literal '*.' in output)")

	// Preserved cases: each wildcard appears as a literal in its own ACL line.
	require.Contains(t, out, " *.\n", "2-char '*.' preserved as literal")
	require.Contains(t, out, " foo.com\n", "non-wildcard preserved as literal")
	require.Contains(t, out, " *foo\n", "wildcard without '.' preserved as literal")
}

// Mutation kill for dnsmasq.go:31 — same wildcard parsing in dnsmasq render.
func TestRenderDNSMasq_WildcardEdgeCases(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.example.com"}}}
	policy := security.Defaults("standard")
	policy.AllowDNSSuffixMatch = true
	policy.WildcardEntries = []string{
		"*.amazonaws.com",
		"*.",
		"foo.com",
		"*foo",
	}
	out := string(RenderDNSMasq(r, policy))
	// Only "*.amazonaws.com" should produce a server=/amazonaws.com/ line.
	require.Contains(t, out, "server=/amazonaws.com/",
		"wildcard *.amazonaws.com → suffix-stripped to amazonaws.com")
	require.NotContains(t, out, "server=//",
		"2-char '*.' must NOT produce an empty-suffix server line")
	require.NotContains(t, out, "server=/foo.com/",
		"non-wildcard must NOT produce a server line")
	require.NotContains(t, out, "server=/foo/",
		"'*foo' (no dot) must NOT produce a server line")
}

// TestRender_SSRFGuard_TCPEgress verifies that Render returns an error when
// tcp_egress contains a literal private IP (10.0.0.5:5432).
func TestRender_SSRFGuard_TCPEgress(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
	}
	_, err := g.Render("spawn-ssrf-tcp", r, security.Defaults("strict"))
	require.Error(t, err, "literal private IP in tcp_egress must be rejected")
	require.Contains(t, err.Error(), "security:")
}

// TestRender_SSRFGuard_HTTPEgress verifies that Render returns an error when
// http_egress contains a literal private IP (169.254.169.254).
func TestRender_SSRFGuard_HTTPEgress(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{
		HTTPEgress: []string{"169.254.169.254"},
	}
	_, err := g.Render("spawn-ssrf-http", r, security.Defaults("strict"))
	require.Error(t, err, "literal cloud metadata IP in http_egress must be rejected")
	require.Contains(t, err.Error(), "security:")
}

// TestRender_SSRFGuard_AllowedViaPolicy verifies that a private IP is accepted
// when the policy's AllowedPrivateCIDRs covers it.
func TestRender_SSRFGuard_AllowedViaPolicy(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	r := &runneryml.Runner{
		TCPEgress: []string{"10.0.0.5:5432"},
	}
	_, allowedNet, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	p := security.Defaults("strict")
	p.AllowedPrivateCIDRs = []*net.IPNet{allowedNet}
	_, err = g.Render("spawn-ssrf-allowed", r, p)
	require.NoError(t, err, "10.0.0.5 allowed by operator-defined CIDR must not be rejected")
}

func TestRender_DNSMasqWriteFails(t *testing.T) {
	dir := t.TempDir()
	g := NewFSGenerator(dir)
	spawnDir := filepath.Join(dir, "spawn-2")
	require.NoError(t, os.MkdirAll(spawnDir, 0o755))
	// Pre-create dnsmasq.conf as a directory.
	require.NoError(t, os.MkdirAll(filepath.Join(spawnDir, "dnsmasq.conf"), 0o755))

	_, err := g.Render("spawn-2", &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"x"}}}, security.Defaults("strict"))
	require.Error(t, err)
}
