package egress

import (
	"bytes"
	"fmt"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderSquid produces a squid configuration with the project's egress
// domains and any wildcard entries (if the resolved policy permits).
func RenderSquid(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure squid.conf — generated per-spawn. Do not edit.\n")
	b.WriteString("http_port 3128\n")
	b.WriteString("acl localnet src 0.0.0.0/0\n")

	// Project allowlist (exact-match domains).
	b.WriteString("acl allowed_domains dstdomain\n")
	for _, d := range r.Egress.AllowDomains {
		fmt.Fprintf(&b, "acl allowed_domains dstdomain .%s\n", d)
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
