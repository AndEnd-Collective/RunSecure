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

// reCIDR matches canonical CIDR notation produced by (*net.IPNet).String():
// IPv4 "d.d.d.d/p" or IPv6 "h::h/p". Rejects embedded newlines, spaces, or
// any other character that could inject a second squid directive.
var reCIDR = regexp.MustCompile(`^[0-9a-fA-F:.]+/[0-9]{1,3}$`)

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

	// Operator-approved private CIDRs (allow_private_cidrs scope override).
	// Emit the exemption allow BEFORE the deny so that Squid's first-match-wins
	// evaluation allows the approved ranges while every other private destination
	// (including IMDS 169.254.169.254) still hits the deny below.
	//
	// Security invariant: the CIDR text comes from *net.IPNet.String() which
	// always produces canonical, safe output ("a.b.c.d/prefix"). We assert
	// the canonical form contains no spaces, newlines, or shell metacharacters
	// before emitting — defence against future callers that might pass
	// user-controlled strings.
	var emittedAllowedPrivate int
	for _, ipnet := range p.AllowedPrivateCIDRs {
		cidr := ipnet.String()
		// net.IPNet.String() is always "a.b.c.d/prefix" or "a:b::c/prefix";
		// reject anything that deviates from this safe form.
		if !reCIDR.MatchString(cidr) {
			// Silently skip malformed entries — fail-safe (deny wins).
			continue
		}
		fmt.Fprintf(&b, "acl rs_allowed_private dst %s\n", cidr)
		emittedAllowedPrivate++
	}
	// Emit the allow rule only when at least one valid approved CIDR was emitted.
	// This ensures no orphaned http_access allow rule appears without a matching ACL.
	if emittedAllowedPrivate > 0 {
		b.WriteString("http_access allow rs_allowed_private\n")
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
	// Runtime paths that must be writable even on a read-only rootfs.
	// The proxy container is spawned with tmpfs on /var/run/squid and
	// /var/log/squid; setting these explicitly avoids squid falling back to
	// its compiled-in default (/run/squid.pid) which is root-only on Debian.
	b.WriteString("pid_filename /var/run/squid/squid.pid\n")
	b.WriteString("access_log stdio:/var/log/squid/access.log\n")
	b.WriteString("cache_log /var/log/squid/cache.log\n")
	b.WriteString("cache deny all\n")
	b.WriteString("coredump_dir /var/spool/squid\n")
	return b.Bytes()
}
