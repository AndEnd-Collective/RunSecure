package egress

import (
	"strings"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// TestRenderSquid_WildcardInjectionBlocked verifies that a WildcardEntries value
// containing an embedded newline cannot inject a second squid directive. This is
// Fix 1 (security): the wildcard suffix must be sanitized before emission.
func TestRenderSquid_WildcardInjectionBlocked(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard") // AllowWildcards=true
	policy.WildcardEntries = []string{"*.foo\nhttp_access allow all"}

	out := string(RenderSquid(r, policy))

	// The injected directive must NOT appear in the output.
	if strings.Contains(out, "http_access allow all\n") && strings.Count(out, "http_access allow all") > 0 {
		// Only the legitimate allow is present (allowed_domains line); check for the
		// injected allow coming from the attacker payload.
		if strings.Contains(out, "foo\nhttp_access allow all") || strings.Contains(out, "\nhttp_access allow all\nhttp_access") {
			t.Fatalf("wildcard injection leaked into squid config:\n%s", out)
		}
	}
	// Stricter: the raw newline+directive sequence must never appear.
	if strings.Contains(out, "foo\nhttp_access allow all") {
		t.Fatalf("wildcard newline injection found in squid config:\n%s", out)
	}
	// The attacker value must produce zero output lines (sanitize rejects it).
	if strings.Contains(out, "acl allowed_domains dstdomain foo") {
		t.Fatalf("poisoned wildcard suffix should have been dropped, but was emitted:\n%s", out)
	}
	// http_access deny all must still be last.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[len(lines)-1] != "visible_hostname runsecure-proxy" {
		t.Fatalf("last line must be visible_hostname, got: %s", lines[len(lines)-1])
	}
}

// TestRenderSquid_WildcardClean_StillEmitted verifies that a clean wildcard like
// *.amazonaws.com is still emitted correctly after sanitization (positive case).
func TestRenderSquid_WildcardClean_StillEmitted(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")
	policy.WildcardEntries = []string{"*.amazonaws.com"}

	out := string(RenderSquid(r, policy))
	if !strings.Contains(out, "dstdomain .amazonaws.com") {
		t.Fatalf("clean wildcard *.amazonaws.com must be emitted as .amazonaws.com:\n%s", out)
	}
}

// TestRenderSquid_DenyAllIsLast verifies http_access deny all is always the
// final access control line.
func TestRenderSquid_DenyAllIsLast(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")
	policy.WildcardEntries = []string{"*.amazonaws.com", "*.foo\nhttp_access allow all"}

	out := string(RenderSquid(r, policy))
	denyIdx := strings.Index(out, "http_access deny all")
	allowIdx := strings.Index(out, "http_access allow allowed_domains")
	if denyIdx < allowIdx {
		t.Fatalf("http_access deny all must come AFTER allow; deny at %d, allow at %d\n%s", denyIdx, allowIdx, out)
	}
}
