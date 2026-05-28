package egress

import (
	"bytes"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
)

// RenderHAProxy produces a haproxy configuration. Plan A only emits a
// minimal scaffold; richer TCP allowlists are a future extension keyed
// off a runner.yml field we haven't introduced yet.
func RenderHAProxy(_ *runneryml.Runner, _ security.Policy) []byte {
	var b bytes.Buffer
	b.WriteString("# RunSecure haproxy.cfg — generated per-spawn. Do not edit.\n")
	b.WriteString("global\n")
	b.WriteString("  maxconn 256\n\n")
	b.WriteString("defaults\n")
	b.WriteString("  mode tcp\n")
	b.WriteString("  timeout connect 10s\n")
	b.WriteString("  timeout client  60s\n")
	b.WriteString("  timeout server  60s\n")
	return b.Bytes()
}
