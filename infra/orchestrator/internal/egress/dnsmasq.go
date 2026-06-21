package egress

import (
	"bytes"
	"fmt"
	"net"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderDNSMasq generates a dnsmasq configuration that:
//   - Forwards queries only for explicitly-allowed domains (ResolvedHTTPEgress
//     + host parts of TCPEgress) via per-name server stanzas.
//   - Emits upstream resolvers from Runner.DNS.Servers when provided (each
//     must parse as a valid IP; hostnames are silently dropped). Falls back to
//     hardcoded 1.1.1.1 / 9.9.9.9 when the list is empty.
//   - Emits `log-queries` when Runner.DNS.LogQueries is nil or true; emits
//     `# log-queries disabled` when explicitly false.
//   - Suffix-matches via `server=/<SUFFIX>/<upstream>` only if the resolved
//     policy permits and the entry starts with "*."; the suffix is sanitized.
//   - Default-deny via `local=/./` (NXDOMAIN for everything not listed).
//
// NOTE: hosts_file and whitelist_file from Runner.DNS are out of scope for
// 2.0.0; the legacy run.sh path still supports them. They will be consumed
// here in a 2.0.x follow-up.
func RenderDNSMasq(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure dnsmasq.conf — generated per-spawn. Do not edit.\n")
	b.WriteString("no-resolv\n")

	// Resolve upstream servers: use Runner.DNS.Servers when provided,
	// otherwise fall back to the hardcoded defaults.
	upstreams := resolveUpstreams(r)
	for _, srv := range upstreams {
		fmt.Fprintf(&b, "server=%s\n", srv)
	}
	b.WriteString("\n")

	// log-queries: enabled unless Runner.DNS.LogQueries is explicitly false.
	if r.DNS.LogQueries != nil && !*r.DNS.LogQueries {
		b.WriteString("# log-queries disabled\n")
	} else {
		b.WriteString("log-queries\n")
	}
	b.WriteString("\n")

	// Per-domain server stanzas: forward queries for allowed names to the
	// first upstream; all others receive NXDOMAIN via local=/./.
	// Use the first upstream as the forwarding target for per-name stanzas.
	forwardTo := "1.1.1.1"
	if len(upstreams) > 0 {
		forwardTo = upstreams[0]
	}

	for _, d := range r.ResolvedHTTPEgress() {
		if clean := sanitizeDomain(d); clean != "" {
			fmt.Fprintf(&b, "server=/%s/%s\n", clean, forwardTo)
		}
	}

	// Wildcard suffix entries only if policy permits suffix-match AND entry
	// starts with "*.". Sanitize the suffix AFTER stripping "*." so embedded
	// newlines or metacharacters are rejected.
	if p.AllowDNSSuffixMatch {
		for _, w := range p.WildcardEntries {
			if len(w) > 2 && w[0] == '*' && w[1] == '.' {
				suffix := w[2:]
				if clean := sanitizeDomain(suffix); clean != "" {
					fmt.Fprintf(&b, "server=/%s/%s\n", clean, forwardTo)
				}
			}
		}
	}

	// Default-deny: NXDOMAIN for anything not listed.
	b.WriteString("\n# Default-deny: NXDOMAIN for anything not listed.\n")
	b.WriteString("local=/./\n")

	return b.Bytes()
}

// resolveUpstreams returns the validated DNS upstream IPs. Runner.DNS.Servers
// entries that are not valid IPs are silently dropped. When the list is empty
// (or all entries are invalid), the hardcoded defaults are returned.
func resolveUpstreams(r *runneryml.Runner) []string {
	if len(r.DNS.Servers) > 0 {
		var valid []string
		for _, s := range r.DNS.Servers {
			if net.ParseIP(s) != nil {
				valid = append(valid, s)
			}
		}
		if len(valid) > 0 {
			return valid
		}
	}
	return []string{"1.1.1.1", "9.9.9.9"}
}
