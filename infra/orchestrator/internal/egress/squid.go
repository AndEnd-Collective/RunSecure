package egress

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// reDomain matches valid domain names for egress filtering. Same pattern as
// runneryml.go for consistency. Rejects any domain with newlines or other
// injection characters.
var reDomain = regexp.MustCompile(`^\.?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// sanitizeDomain returns the domain if it passes the domain regex, otherwise
// returns an empty string. This prevents config injection via domains with
// newlines or other metacharacters.
func sanitizeDomain(d string) string {
	if reDomain.MatchString(d) {
		return d
	}
	return ""
}

// privateRanges lists private, loopback, link-local, and special-use IP
// ranges that runners must never reach. Squid resolves the destination IP and
// denies if it falls in one of these CIDRs — independent of the domain
// allowlist, providing DNS-rebinding defense for HTTP.
var privateRanges = []string{
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local / cloud IMDS
	"10.0.0.0/8",     // RFC-1918
	"172.16.0.0/12",  // RFC-1918
	"192.168.0.0/16", // RFC-1918
	"0.0.0.0/8",      // "this" network
	"::1/128",        // IPv6 loopback
	"fe80::/10",      // IPv6 link-local
	"fc00::/7",       // IPv6 unique-local
}

// RenderSquid produces a squid configuration with the project's egress
// domains and any wildcard entries (if the resolved policy permits).
// Reads domains from ResolvedHTTPEgress() to support the new schema.
func RenderSquid(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure squid.conf — generated per-spawn. Do not edit.\n")
	b.WriteString("http_port 3128\n")

	// Explicit deny ACL for private/special-use IP ranges. Placed before the
	// domain allowlist so that an allowed hostname that DNS-resolves to a
	// private IP is still blocked (DNS-rebinding defense).
	for _, cidr := range privateRanges {
		fmt.Fprintf(&b, "acl rs_private_dst dst %s\n", cidr)
	}
	b.WriteString("http_access deny rs_private_dst\n")

	// Collect all permitted domains first, then emit the ACL and allow rule
	// only when there are entries. An empty "acl allowed_domains dstdomain"
	// line with no targets is valid squid syntax but cosmetically wrong and
	// potentially confusing in a security config.
	var domainLines []string
	for _, d := range r.ResolvedHTTPEgress() {
		if clean := sanitizeDomain(d); clean != "" {
			domainLines = append(domainLines, fmt.Sprintf("acl allowed_domains dstdomain .%s\n", clean))
		}
	}
	// Wildcard entries only if the resolved policy allows them.
	if p.AllowWildcards {
		for _, w := range p.WildcardEntries {
			// e.g. "*.amazonaws.com" → ".amazonaws.com" suffix match in squid syntax
			suffix := w
			if len(w) > 2 && w[0] == '*' && w[1] == '.' {
				suffix = w[1:]
			}
			// Sanitize AFTER stripping the "*." prefix so embedded
			// newlines or metacharacters in the suffix are rejected.
			if clean := sanitizeDomain(suffix); clean != "" {
				domainLines = append(domainLines, fmt.Sprintf("acl allowed_domains dstdomain %s\n", clean))
			}
		}
	}
	for _, line := range domainLines {
		b.WriteString(line)
	}
	if len(domainLines) > 0 {
		b.WriteString("http_access allow allowed_domains\n")
	}
	b.WriteString("http_access deny all\n")
	b.WriteString("visible_hostname runsecure-proxy\n")
	return b.Bytes()
}
