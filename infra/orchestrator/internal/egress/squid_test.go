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

// TestRenderSquid_PrivateIPDenyPrecedesAllow verifies that an explicit
// "http_access deny rs_private_dst" line is emitted BEFORE the
// "http_access allow allowed_domains" line. This gives defense-in-depth
// against DNS-rebinding: even if a hostname resolves to a private IP, Squid
// will deny the connection based on the resolved destination address.
func TestRenderSquid_PrivateIPDenyPrecedesAllow(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")

	out := string(RenderSquid(r, policy))

	// The private-dst ACL definition must be present.
	if !strings.Contains(out, "acl rs_private_dst dst") {
		t.Fatalf("expected 'acl rs_private_dst dst' in squid config:\n%s", out)
	}

	// The explicit deny must be present.
	const denyLine = "http_access deny rs_private_dst"
	if !strings.Contains(out, denyLine) {
		t.Fatalf("expected %q in squid config:\n%s", denyLine, out)
	}

	// The deny must come BEFORE the allow.
	denyIdx := strings.Index(out, denyLine)
	allowIdx := strings.Index(out, "http_access allow allowed_domains")
	if denyIdx >= allowIdx {
		t.Fatalf("private-IP deny (pos %d) must precede allow (pos %d):\n%s", denyIdx, allowIdx, out)
	}
}

// TestRenderSquid_PrivateIPRangesCovered verifies that all required private and
// special-use IP ranges appear in the rs_private_dst ACL.
func TestRenderSquid_PrivateIPRangesCovered(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")

	out := string(RenderSquid(r, policy))

	required := []string{
		"127.0.0.0/8",
		"169.254.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"0.0.0.0/8",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range required {
		if !strings.Contains(out, cidr) {
			t.Errorf("private-IP range %q missing from squid config:\n%s", cidr, out)
		}
	}
}
