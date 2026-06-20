package egress

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderHAProxy produces a haproxy configuration with per-port TCP frontends
// and backends from the runner's TCP egress list. Emits one frontend/backend
// pair per tcp_egress entry, plus a resolvers section for runtime DNS resolution.
func RenderHAProxy(r *runneryml.Runner, _ security.Policy) []byte {
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
		fmt.Fprintf(&b, "frontend tcp_%s\n  bind :%s\n  default_backend backend_%s\n\n", port, port, port)
		fmt.Fprintf(&b, "backend backend_%s\n  server srv_%s %s:%s check resolvers default_dns init-addr none\n\n", port, port, host, port)
	}

	return b.Bytes()
}

// isHostPortSafe verifies that host and port strings are safe to interpolate
// into HAProxy directives. Rejects newlines, carriage returns, spaces, and
// hash characters that could break the config syntax.
func isHostPortSafe(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	for _, c := range host + port {
		if c == '\n' || c == '\r' || c == ' ' || c == '#' || c == '\t' {
			return false
		}
	}
	return true
}
