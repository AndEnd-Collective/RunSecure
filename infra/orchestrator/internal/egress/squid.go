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

// GitHubCoreDomains is the set of domains the GitHub Actions control-plane
// requires for every runner — regardless of what runner.yml http_egress
// contains. Without these domains a JIT runner registers with GitHub but
// cannot reach the broker / VSTOKEN endpoint and immediately goes offline
// without picking up any queued job.
//
// MUST be kept in sync with the github_core ACL in
// infra/squid/base.conf (the one-shot run.sh path). When either list
// changes, update both files.
var GitHubCoreDomains = []string{
	".github.com",
	"api.github.com",
	".githubusercontent.com",
	".actions.githubusercontent.com",
	".objects.githubusercontent.com",
	".github.githubassets.com",
	".ghcr.io",
	".pkg.github.com",
	".pipelines.actions.githubusercontent.com",
	".results-receiver.actions.githubusercontent.com",
	".vstoken.actions.githubusercontent.com",
	// GitHub Actions uses dynamically named Azure Blob hosts for job logs,
	// artifacts, and caches. GitHub documents the full suffix as required for
	// self-hosted runners, so an account-specific hostname is not sufficient.
	".blob.core.windows.net",
}

// BuiltInEgressDomains is the package-registry and CI-tool baseline shipped in
// infra/squid/base.conf. The persistent orchestrator renders Squid from Go
// rather than reading that file, so these domains must be carried explicitly
// to keep the one-shot and persistent backends behaviorally identical.
var BuiltInEgressDomains = []string{
	".npmjs.org",
	".pypi.org",
	".files.pythonhosted.org",
	".crates.io",
	".nodejs.org",
	".nodesource.com",
	".playwright.azureedge.net",
	".googleapis.com",
	".google.com",
	".semgrep.dev",
	".rustup.rs",
	".rust-lang.org",
}

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
	b.WriteString("acl SSL_ports port 443\n")
	b.WriteString("acl Safe_ports port 80\n")
	b.WriteString("acl Safe_ports port 443\n")
	b.WriteString("acl CONNECT method CONNECT\n")

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

	// Keep public-domain handling aligned with base.conf: an allowlisted
	// hostname never authorizes HTTP or CONNECT on an arbitrary port. The
	// operator-approved private CIDR exemption intentionally precedes these
	// denies so exact local services such as Vladislav's Proxpi gateway on
	// port 3141 remain reachable. Every public-domain allow remains below.
	b.WriteString("http_access deny !Safe_ports\n")
	b.WriteString("http_access deny CONNECT !SSL_ports\n")

	b.WriteString("http_access deny rs_private_dst\n")

	// GitHub Actions control-plane baseline (unconditional — every runner
	// needs these domains to register, receive the VSTOKEN, stream logs, and
	// report job results regardless of what runner.yml http_egress contains).
	//
	// Placed AFTER the private-IP deny (which is dst-IP based) so that a
	// GitHub hostname that DNS-resolves to a private IP is still blocked by
	// the dst-IP rule above before this allow is evaluated — maintaining the
	// DNS-rebinding defense. GitHubCoreDomains are dstdomain ACLs, so Squid
	// applies them on the CONNECT hostname, not the resolved IP; the ordering
	// matters only for dst (IP) ACLs, not dstdomain ones, but we keep
	// private-deny first as defence-in-depth.
	//
	// Sync: infra/squid/base.conf's github_core ACL must list the same
	// domains (the one-shot run.sh path). See GitHubCoreDomains constant.
	for _, d := range GitHubCoreDomains {
		if clean := sanitizeDomain(d); clean != "" {
			fmt.Fprintf(&b, "acl rs_github_core dstdomain %s\n", clean)
		}
	}
	b.WriteString("http_access allow rs_github_core\n")

	// Package registries and common CI tools are part of RunSecure's built-in
	// egress contract. The legacy one-shot path gets these from base.conf; emit
	// the same baseline here so persistent Compose/Kubernetes runners do not
	// unexpectedly deny package downloads when runner.yml has no custom egress.
	for _, d := range BuiltInEgressDomains {
		if clean := sanitizeDomain(d); clean != "" {
			fmt.Fprintf(&b, "acl rs_builtin_egress dstdomain %s\n", clean)
		}
	}
	b.WriteString("http_access allow rs_builtin_egress\n")

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
