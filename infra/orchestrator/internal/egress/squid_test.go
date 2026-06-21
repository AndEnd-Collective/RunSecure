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
	// The runtime-path directives must appear after all access rules.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	lastLine := lines[len(lines)-1]
	if lastLine != "coredump_dir /var/spool/squid" {
		t.Fatalf("last line must be coredump_dir directive, got: %s", lastLine)
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

// Test C: empty http_egress with AllowWildcards=false must not emit a bare
// "acl allowed_domains dstdomain" line, but must still emit "http_access deny all".
func TestRenderSquid_EmptyHTTPEgress_NoBareACL(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("standard")
	policy.AllowWildcards = false
	policy.WildcardEntries = nil

	out := string(RenderSquid(r, policy))

	if strings.Contains(out, "acl allowed_domains dstdomain\n") {
		t.Fatalf("bare 'acl allowed_domains dstdomain' (empty ACL) must not be emitted:\n%s", out)
	}
	if !strings.Contains(out, "http_access deny all") {
		t.Fatalf("http_access deny all must always be present:\n%s", out)
	}
	if strings.Contains(out, "http_access allow allowed_domains") {
		t.Fatalf("http_access allow allowed_domains must not be emitted when no domains:\n%s", out)
	}
	if strings.Contains(out, "acl localnet") {
		t.Fatalf("dead 'acl localnet' line must not appear in output:\n%s", out)
	}
}

// Test D: non-empty http_egress must still emit allow allowed_domains (regression guard).
func TestRenderSquid_NonEmpty_EmitsAllow(t *testing.T) {
	r := &runneryml.Runner{HTTPEgress: []string{"api.github.com"}}
	policy := security.Defaults("standard")

	out := string(RenderSquid(r, policy))

	if !strings.Contains(out, "acl allowed_domains dstdomain .api.github.com") {
		t.Fatalf("expected 'acl allowed_domains dstdomain .api.github.com' in output:\n%s", out)
	}
	if !strings.Contains(out, "http_access allow allowed_domains") {
		t.Fatalf("expected 'http_access allow allowed_domains' in output:\n%s", out)
	}
	if !strings.Contains(out, "http_access deny all") {
		t.Fatalf("expected 'http_access deny all' in output:\n%s", out)
	}
	if strings.Contains(out, "acl localnet") {
		t.Fatalf("dead 'acl localnet' line must not appear in output:\n%s", out)
	}
}
