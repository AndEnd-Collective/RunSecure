package egress

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderHAProxy produces a haproxy configuration with per-port TCP frontends
// and backends from the runner's TCP egress list. Emits one frontend/backend
// pair per tcp_egress entry, plus a resolvers section for runtime DNS resolution.
func RenderHAProxy(r *runneryml.Runner, p security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure haproxy.cfg — generated per-spawn. Do not edit.\n")
	b.WriteString("global\n  maxconn 256\n\n")
	b.WriteString("defaults\n  mode tcp\n  timeout connect 10s\n  timeout client 60s\n  timeout server 60s\n\n")

	// Runtime DNS resolution via the container's embedded resolver.
	b.WriteString("resolvers default_dns\n  parse-resolv-conf\n  resolve_retries 3\n  timeout retry 1s\n  hold valid 10s\n\n")

	for _, e := range r.TCPEgress {
		// Entries are pre-validated (host:port, no metacharacters) by
		// runneryml.ValidateEgress; defense-in-depth: skip anything unexpected.
		i := strings.LastIndex(e, ":")
		if i < 1 {
			continue
		}
		host, port := e[:i], e[i+1:]
		if !isHostPortSafe(host, port) {
			continue
		}
		fmt.Fprintf(&b, "frontend tcp_%s\n  bind :%s\n  tcp-request inspect-delay 5s\n", port, port)
		// Resolve once for this connection and check the very address used by
		// set-dst. A backend hostname/resolvers or health check would introduce
		// an unchecked second resolution and permit private DNS rebinding.
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			family := "ipv6"
			if ip.To4() != nil {
				family = "ipv4"
			}
			fmt.Fprintf(&b, "  tcp-request content set-var(sess.rs_dst) %s(%s)\n", family, ip.String())
		} else {
			fmt.Fprintf(&b, "  tcp-request content do-resolve(sess.rs_dst,default_dns,ipv4) str(%s)\n", host)
		}
		b.WriteString("  tcp-request content reject unless { var(sess.rs_dst) -m found }\n")
		for _, cidr := range security.BlockedEgressCIDRs() {
			fmt.Fprintf(&b, "  acl rs_private_dst var(sess.rs_dst) -m ip %s\n", cidr)
		}
		allowed := false
		for _, network := range p.AllowedPrivateCIDRs {
			cidr := network.String()
			if !reCIDR.MatchString(cidr) {
				continue
			}
			fmt.Fprintf(&b, "  acl rs_allowed_private var(sess.rs_dst) -m ip %s\n", cidr)
			allowed = true
		}
		b.WriteString("  tcp-request content reject if rs_private_dst")
		if allowed {
			b.WriteString(" !rs_allowed_private")
		}
		b.WriteString("\n  tcp-request content set-dst var(sess.rs_dst)\n")
		fmt.Fprintf(&b, "  default_backend backend_%s\n\n", port)
		fmt.Fprintf(&b, "backend backend_%s\n  server srv_%s 0.0.0.0:%s\n\n", port, port, port)
	}

	return b.Bytes()
}

var reHAProxyHost = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)

// isHostPortSafe admits only addresses and numeric ports that cannot change a
// directive or the HAProxy sample expression containing the hostname.
func isHostPortSafe(host, port string) bool {
	if !reHAProxyHost.MatchString(host) && net.ParseIP(strings.Trim(host, "[]")) == nil {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
