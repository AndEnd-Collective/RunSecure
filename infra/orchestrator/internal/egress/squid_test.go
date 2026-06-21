package egress

import (
	"net"
	"strings"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// mustParseCIDR is a test helper that parses a CIDR string and panics on error.
func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic("test: invalid CIDR: " + s + ": " + err.Error())
	}
	return ipnet
}

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
	// http_access deny all must appear BEFORE any runtime-path directive.
	// This is the real invariant: access control lines must not be split by
	// or follow operational directives like pid_filename, access_log, etc.
	// Using a positional index check is robust regardless of trailing content.
	denyAllIdx := strings.Index(out, "http_access deny all")
	for _, runtimeDirective := range []string{
		"pid_filename ",
		"access_log ",
		"cache_log ",
		"coredump_dir ",
	} {
		if idx := strings.Index(out, runtimeDirective); idx != -1 && idx < denyAllIdx {
			t.Fatalf("%q (pos %d) must not appear before 'http_access deny all' (pos %d):\n%s",
				runtimeDirective, idx, denyAllIdx, out)
		}
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

// ─── allow_private_cidrs exemption tests (issue #47) ─────────────────────────

// TestRenderSquid_AllowedPrivateCIDR_EmittedBeforeDeny verifies the positive case:
// with AllowedPrivateCIDRs=[172.17.0.0/16], the rendered config contains:
//  1. acl rs_allowed_private dst 172.17.0.0/16
//  2. http_access allow rs_allowed_private
//  3. Both of the above appear BEFORE http_access deny rs_private_dst
func TestRenderSquid_AllowedPrivateCIDR_EmittedBeforeDeny(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict")
	policy.AllowedPrivateCIDRs = []*net.IPNet{mustParseCIDR("172.17.0.0/16")}

	out := string(RenderSquid(r, policy))

	// 1. ACL definition must be present.
	const aclLine = "acl rs_allowed_private dst 172.17.0.0/16"
	if !strings.Contains(out, aclLine) {
		t.Fatalf("expected %q in squid config:\n%s", aclLine, out)
	}

	// 2. The allow rule must be present.
	const allowLine = "http_access allow rs_allowed_private"
	if !strings.Contains(out, allowLine) {
		t.Fatalf("expected %q in squid config:\n%s", allowLine, out)
	}

	// 3. The allow must precede the deny (first-match-wins).
	allowIdx := strings.Index(out, allowLine)
	denyIdx := strings.Index(out, "http_access deny rs_private_dst")
	if allowIdx >= denyIdx {
		t.Fatalf("http_access allow rs_allowed_private (pos %d) must precede "+
			"http_access deny rs_private_dst (pos %d):\n%s", allowIdx, denyIdx, out)
	}
}

// TestRenderSquid_AllowedPrivateCIDR_MultipleEntries verifies that multiple
// approved CIDRs each emit their own acl line and share a single allow rule.
func TestRenderSquid_AllowedPrivateCIDR_MultipleEntries(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict")
	policy.AllowedPrivateCIDRs = []*net.IPNet{
		mustParseCIDR("172.17.0.0/16"),
		mustParseCIDR("192.168.100.0/24"),
	}

	out := string(RenderSquid(r, policy))

	for _, cidr := range []string{"172.17.0.0/16", "192.168.100.0/24"} {
		line := "acl rs_allowed_private dst " + cidr
		if !strings.Contains(out, line) {
			t.Errorf("expected %q in squid config:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "http_access allow rs_allowed_private") {
		t.Fatalf("expected 'http_access allow rs_allowed_private':\n%s", out)
	}
}

// TestRenderSquid_EmptyAllowedPrivateCIDRs_NoExemptionEmitted is the negative
// case / default-deny guard: when AllowedPrivateCIDRs is nil/empty, NO
// rs_allowed_private lines must appear in the output. The deny remains intact.
func TestRenderSquid_EmptyAllowedPrivateCIDRs_NoExemptionEmitted(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict") // AllowedPrivateCIDRs = nil

	out := string(RenderSquid(r, policy))

	if strings.Contains(out, "rs_allowed_private") {
		t.Fatalf("rs_allowed_private must NOT appear when AllowedPrivateCIDRs is empty:\n%s", out)
	}
	// The deny must still be present (default-deny intact).
	if !strings.Contains(out, "http_access deny rs_private_dst") {
		t.Fatalf("http_access deny rs_private_dst must always be present:\n%s", out)
	}
}

// TestRenderSquid_IMDS_NotCarvedOut_AttackerTest is the attacker scenario:
// even with AllowedPrivateCIDRs=[172.17.0.0/16], the IMDS address
// 169.254.169.254 is NOT in the approved range and must remain covered by
// the rs_private_dst deny — confirming the deny is still emitted and IMDS
// is not exempted.
func TestRenderSquid_IMDS_NotCarvedOut_AttackerTest(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict")
	policy.AllowedPrivateCIDRs = []*net.IPNet{mustParseCIDR("172.17.0.0/16")}

	out := string(RenderSquid(r, policy))

	// rs_private_dst ACL must still include 169.254.0.0/16 (IMDS range).
	if !strings.Contains(out, "acl rs_private_dst dst 169.254.0.0/16") {
		t.Fatalf("IMDS range 169.254.0.0/16 must remain in rs_private_dst:\n%s", out)
	}
	// The deny must still be present (IMDS is not carved out).
	if !strings.Contains(out, "http_access deny rs_private_dst") {
		t.Fatalf("http_access deny rs_private_dst must be present even with allowed CIDRs:\n%s", out)
	}
	// IMDS must NOT appear in the rs_allowed_private ACL.
	if strings.Contains(out, "acl rs_allowed_private dst 169.254") {
		t.Fatalf("IMDS 169.254.x.x must NOT appear in rs_allowed_private:\n%s", out)
	}
	// Allow must come before deny (first-match wins for 172.17.x.x).
	const allowLine = "http_access allow rs_allowed_private"
	allowIdx := strings.Index(out, allowLine)
	denyIdx := strings.Index(out, "http_access deny rs_private_dst")
	if allowIdx < 0 || denyIdx < 0 {
		t.Fatalf("expected both allow and deny lines:\n%s", out)
	}
	if allowIdx >= denyIdx {
		t.Fatalf("allow (pos %d) must precede deny (pos %d):\n%s", allowIdx, denyIdx, out)
	}
}

// TestRenderSquid_AllowedPrivateCIDR_IPv6 verifies that an IPv6 approved CIDR
// is correctly emitted (e.g., operator approves an IPv6 private range).
func TestRenderSquid_AllowedPrivateCIDR_IPv6(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict")
	// fc00::/7 is in the private range but operator-approved here.
	policy.AllowedPrivateCIDRs = []*net.IPNet{mustParseCIDR("fc00::/7")}

	out := string(RenderSquid(r, policy))

	const aclLine = "acl rs_allowed_private dst fc00::/7"
	if !strings.Contains(out, aclLine) {
		t.Fatalf("expected %q for IPv6 approved CIDR:\n%s", aclLine, out)
	}
	if !strings.Contains(out, "http_access allow rs_allowed_private") {
		t.Fatalf("expected allow rule for IPv6 approved CIDR:\n%s", out)
	}
	// rs_private_dst must still cover fc00::/7 (the general deny remains).
	if !strings.Contains(out, "acl rs_private_dst dst fc00::/7") {
		t.Fatalf("fc00::/7 must remain in rs_private_dst general deny:\n%s", out)
	}
}

// TestRenderSquid_AllowedPrivateCIDR_MalformedSkipped verifies that a
// *net.IPNet whose String() returns a non-canonical value (e.g. "<nil>") is
// silently skipped rather than injected into the squid config. This exercises
// the reCIDR guard's continue branch (defensive: net.IPNet.String() always
// produces canonical output in normal usage; this covers the paranoia path).
func TestRenderSquid_AllowedPrivateCIDR_MalformedSkipped(t *testing.T) {
	r := &runneryml.Runner{}
	policy := security.Defaults("strict")
	// Construct a *net.IPNet with an empty IP so .String() returns "<nil>",
	// which fails reCIDR and must be silently skipped.
	malformed := &net.IPNet{IP: net.IP{}, Mask: net.IPMask{0xff, 0xff, 0xff, 0xff}}
	policy.AllowedPrivateCIDRs = []*net.IPNet{malformed}

	out := string(RenderSquid(r, policy))

	// The malformed CIDR must NOT appear in the output.
	if strings.Contains(out, "rs_allowed_private") {
		t.Fatalf("malformed CIDR must be silently skipped; rs_allowed_private must not appear:\n%s", out)
	}
	// The deny must still be present (fail-safe).
	if !strings.Contains(out, "http_access deny rs_private_dst") {
		t.Fatalf("http_access deny rs_private_dst must still be present after malformed CIDR skip:\n%s", out)
	}
}
