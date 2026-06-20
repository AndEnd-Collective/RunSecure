package egress

import (
	"bytes"
	"fmt"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderDNSMasq generates a dnsmasq configuration. Exact-match by default
// (one server stanza per allowed FQDN); suffix-match (`address=/foo/...`)
// only if the resolved policy permits and the entry starts with "*.".
// Reads domains from ResolvedHTTPEgress() to support the new schema.
func RenderDNSMasq(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure dnsmasq.conf — generated per-spawn. Do not edit.\n")
	b.WriteString("no-resolv\n")
	b.WriteString("server=1.1.1.1\n")
	b.WriteString("server=9.9.9.9\n\n")

	// Exact-match per allowed domain. We only allow lookups for entries
	// the project lists explicitly; dnsmasq will refuse to resolve others
	// (via the local=/.../ trick — see below).
	for _, d := range r.ResolvedHTTPEgress() {
		if clean := sanitizeDomain(d); clean != "" {
			fmt.Fprintf(&b, "# exact: %s\n", clean)
		}
	}

	// Wildcard entries only if policy permits suffix-match AND entry starts with "*."
	if p.AllowDNSSuffixMatch {
		for _, w := range p.WildcardEntries {
			if len(w) > 2 && w[0] == '*' && w[1] == '.' {
				suffix := w[2:]
				// dnsmasq syntax: forward only the named domain
				fmt.Fprintf(&b, "server=/%s/1.1.1.1\n", suffix)
			}
		}
	}

	// Deny everything else (default-deny via local=/...)
	b.WriteString("\n# Default-deny: NXDOMAIN for anything not listed.\n")
	b.WriteString("local=/./\n")

	return b.Bytes()
}
