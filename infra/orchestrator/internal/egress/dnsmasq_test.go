package egress

import (
	"strings"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// TestRenderDNSMasq_WildcardInjectionBlocked verifies that a WildcardEntries value
// containing an embedded newline cannot inject a second dnsmasq directive. This is
// Fix 1 (security): the wildcard suffix must be sanitized before emission in dnsmasq.
func TestRenderDNSMasq_WildcardInjectionBlocked(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")
	policy.AllowDNSSuffixMatch = true
	policy.WildcardEntries = []string{"*.foo\nserver=/evil.com/8.8.8.8"}

	out := string(RenderDNSMasq(r, policy))

	// The injected server line must NOT appear.
	if strings.Contains(out, "server=/evil.com/") {
		t.Fatalf("wildcard injection leaked into dnsmasq config:\n%s", out)
	}
	// The raw foo suffix must not appear either.
	if strings.Contains(out, "server=/foo\n") || strings.Contains(out, "server=/foo/") {
		t.Fatalf("poisoned wildcard suffix emitted into dnsmasq config:\n%s", out)
	}
	// Default-deny must still be present.
	if !strings.Contains(out, "local=/./") {
		t.Fatalf("default-deny (local=/./) missing from dnsmasq config:\n%s", out)
	}
}

// TestRenderDNSMasq_WildcardClean_StillEmitted verifies that a clean wildcard is
// still emitted correctly (positive case for Fix 1).
func TestRenderDNSMasq_WildcardClean_StillEmitted(t *testing.T) {
	r := &runneryml.Runner{Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}}}
	policy := security.Defaults("standard")
	policy.AllowDNSSuffixMatch = true
	policy.WildcardEntries = []string{"*.amazonaws.com"}

	out := string(RenderDNSMasq(r, policy))
	if !strings.Contains(out, "server=/amazonaws.com/") {
		t.Fatalf("clean wildcard *.amazonaws.com must be emitted as server=/amazonaws.com/:\n%s", out)
	}
}

// TestRenderDNSMasq_DNS_Servers verifies that Runner.DNS.Servers valid IPs are
// emitted as upstream resolvers, and non-IP values are silently dropped.
// Fix 2 (spec): RenderDNSMasq must consume Runner.DNS.
func TestRenderDNSMasq_DNS_Servers(t *testing.T) {
	boolFalse := false
	r := &runneryml.Runner{
		Egress: runneryml.Egress{AllowDomains: []string{"api.github.com"}},
		DNS: runneryml.DNSConfig{
			Host:    &boolFalse,
			Servers: []string{"10.0.0.53", "not-an-ip", "192.168.1.1"},
		},
	}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))

	// Valid IPs must be emitted.
	if !strings.Contains(out, "server=10.0.0.53") {
		t.Fatalf("valid DNS server 10.0.0.53 must be emitted:\n%s", out)
	}
	if !strings.Contains(out, "server=192.168.1.1") {
		t.Fatalf("valid DNS server 192.168.1.1 must be emitted:\n%s", out)
	}
	// Non-IP must be silently dropped (not emitted as server=).
	if strings.Contains(out, "server=not-an-ip") {
		t.Fatalf("non-IP 'not-an-ip' must NOT be emitted as a server:\n%s", out)
	}
}

// TestRenderDNSMasq_LogQueries_Disabled verifies that log_queries: false emits
// the disabled comment.
func TestRenderDNSMasq_LogQueries_Disabled(t *testing.T) {
	boolFalse := false
	r := &runneryml.Runner{
		DNS: runneryml.DNSConfig{
			LogQueries: &boolFalse,
		},
	}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))
	if !strings.Contains(out, "# log-queries disabled") {
		t.Fatalf("log_queries:false must emit '# log-queries disabled':\n%s", out)
	}
	if strings.Contains(out, "\nlog-queries\n") {
		t.Fatalf("log-queries directive must NOT appear when log_queries=false:\n%s", out)
	}
}

// TestRenderDNSMasq_LogQueries_EnabledByDefault verifies that log-queries is
// enabled when LogQueries is nil (default) or true.
func TestRenderDNSMasq_LogQueries_EnabledByDefault(t *testing.T) {
	// nil case
	r := &runneryml.Runner{}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))
	if !strings.Contains(out, "log-queries") {
		t.Fatalf("log-queries must be enabled by default (nil):\n%s", out)
	}

	// true case
	boolTrue := true
	r2 := &runneryml.Runner{DNS: runneryml.DNSConfig{LogQueries: &boolTrue}}
	out2 := string(RenderDNSMasq(r2, security.Defaults("strict")))
	if !strings.Contains(out2, "log-queries") {
		t.Fatalf("log-queries must be enabled when LogQueries=true:\n%s", out2)
	}
}

// TestRenderDNSMasq_AllowedDomains_Resolvable verifies that allowed domains get
// explicit server stanzas and the default-deny is present for non-listed domains.
func TestRenderDNSMasq_AllowedDomains_Resolvable(t *testing.T) {
	r := &runneryml.Runner{
		Egress: runneryml.Egress{AllowDomains: []string{"api.github.com", "registry.npmjs.org"}},
	}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))

	// Each allowed domain must have a server stanza (forwarded to real upstream).
	if !strings.Contains(out, "server=/api.github.com/") {
		t.Fatalf("allowed domain api.github.com must have a server stanza:\n%s", out)
	}
	if !strings.Contains(out, "server=/registry.npmjs.org/") {
		t.Fatalf("allowed domain registry.npmjs.org must have a server stanza:\n%s", out)
	}
	// Default-deny must still be present.
	if !strings.Contains(out, "local=/./") {
		t.Fatalf("default-deny (local=/./) missing:\n%s", out)
	}
}

// TestRenderDNSMasq_AllowedDomain_InjectionBlocked verifies that a domain
// containing a newline in ResolvedHTTPEgress is rejected before being emitted
// in a server stanza.
func TestRenderDNSMasq_AllowedDomain_InjectionBlocked(t *testing.T) {
	r := &runneryml.Runner{HTTPEgress: []string{"evil.com\nserver=/injected.com/8.8.8.8"}}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))
	if strings.Contains(out, "server=/injected.com/") {
		t.Fatalf("injection via HTTPEgress domain must be blocked:\n%s", out)
	}
}

// TestRenderDNSMasq_NoCustomServers_DefaultUpstreams verifies that when DNS.Servers
// is empty, the hardcoded default upstreams (1.1.1.1, 9.9.9.9) are used.
func TestRenderDNSMasq_NoCustomServers_DefaultUpstreams(t *testing.T) {
	r := &runneryml.Runner{}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))
	if !strings.Contains(out, "server=1.1.1.1") {
		t.Fatalf("default upstream 1.1.1.1 must be present when no custom servers:\n%s", out)
	}
	if !strings.Contains(out, "server=9.9.9.9") {
		t.Fatalf("default upstream 9.9.9.9 must be present when no custom servers:\n%s", out)
	}
}

// TestRenderDNSMasq_CustomServers_OverrideDefaults verifies that when DNS.Servers
// is non-empty, custom IPs replace the hardcoded defaults.
func TestRenderDNSMasq_CustomServers_OverrideDefaults(t *testing.T) {
	r := &runneryml.Runner{
		DNS: runneryml.DNSConfig{Servers: []string{"10.0.0.53"}},
	}
	out := string(RenderDNSMasq(r, security.Defaults("strict")))
	if !strings.Contains(out, "server=10.0.0.53") {
		t.Fatalf("custom DNS server 10.0.0.53 must be emitted:\n%s", out)
	}
	// Default upstreams should NOT appear when custom ones are set.
	if strings.Contains(out, "server=1.1.1.1") {
		t.Fatalf("default upstream 1.1.1.1 must NOT appear when custom servers are set:\n%s", out)
	}
	if strings.Contains(out, "server=9.9.9.9") {
		t.Fatalf("default upstream 9.9.9.9 must NOT appear when custom servers are set:\n%s", out)
	}
}
