package security

import (
	"fmt"
	"net"
	"strings"
)

// blockedRanges is the set of private/special-use IP ranges that are
// blocked by default in egress entries. Built once at package init.
var blockedRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
		"::/128",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// All entries are hard-coded literals; this must never happen.
			panic(fmt.Sprintf("security: failed to parse built-in blocked CIDR %q: %v", cidr, err))
		}
		blockedRanges = append(blockedRanges, network)
	}
}

// extractHost strips an optional :port suffix and IPv6 bracket notation from
// a host string. Returns the bare IP or hostname string.
//
// Examples:
//
//	"10.0.0.5:5432"   → "10.0.0.5"
//	"[::1]:5432"      → "::1"
//	"169.254.169.254" → "169.254.169.254"
//	"::1"             → "::1"  (bare IPv6, no port)
func extractHost(hostport string) string {
	// Handle IPv6 bracket notation: [::1]:port or [::1]
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end > 0 {
			return hostport[1:end]
		}
	}
	// net.SplitHostPort handles IPv4:port, [IPv6]:port, hostname:port correctly.
	// Fall back to returning hostport verbatim if there is no port (bare host or
	// bare IPv6 like "::1" which SplitHostPort cannot parse without brackets).
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// CheckEgressIPLiterals rejects tcp_egress/http_egress hosts that are literal
// IPs in a blocked private/special range not covered by the policy's opt-in.
//
// Hostnames (strings that do not parse as IP addresses) are skipped — only
// literal IPs are evaluated here.
func CheckEgressIPLiterals(hosts []string, p Policy) error {
	for _, h := range hosts {
		bare := extractHost(h)
		ip := net.ParseIP(bare)
		if ip == nil {
			// Not a literal IP — skip; hostname resolution is not our concern.
			continue
		}
		blocked, blockedRange := inBlockedRange(ip)
		if !blocked {
			continue
		}
		if inAllowedCIDRs(ip, p.AllowedPrivateCIDRs) {
			continue
		}
		return fmt.Errorf("security: egress host %q is a literal IP in blocked range %s; use allow_private_cidrs to opt in", h, blockedRange)
	}
	return nil
}

// inBlockedRange reports whether ip falls within any of the built-in blocked
// ranges and returns the matching range string for error messages.
func inBlockedRange(ip net.IP) (bool, *net.IPNet) {
	for _, r := range blockedRanges {
		if r.Contains(ip) {
			return true, r
		}
	}
	return false, nil
}

// inAllowedCIDRs reports whether ip is covered by any operator-provided CIDR.
func inAllowedCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}
