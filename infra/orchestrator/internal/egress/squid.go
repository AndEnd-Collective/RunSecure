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

// RenderSquid produces a squid configuration with the project's egress
// domains and any wildcard entries (if the resolved policy permits).
// Reads domains from ResolvedHTTPEgress() to support the new schema.
func RenderSquid(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure squid.conf — generated per-spawn. Do not edit.\n")
	b.WriteString("http_port 3128\n")
	b.WriteString("acl localnet src 0.0.0.0/0\n")

	// Project allowlist (exact-match domains).
	b.WriteString("acl allowed_domains dstdomain\n")
	for _, d := range r.ResolvedHTTPEgress() {
		if clean := sanitizeDomain(d); clean != "" {
			fmt.Fprintf(&b, "acl allowed_domains dstdomain .%s\n", clean)
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
			fmt.Fprintf(&b, "acl allowed_domains dstdomain %s\n", suffix)
		}
	}

	b.WriteString("http_access allow allowed_domains\n")
	b.WriteString("http_access deny all\n")
	b.WriteString("visible_hostname runsecure-proxy\n")
	return b.Bytes()
}
