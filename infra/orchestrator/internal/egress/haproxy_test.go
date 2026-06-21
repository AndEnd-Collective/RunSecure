package egress

import (
	"strings"
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/stretchr/testify/require"
)

func TestRenderHAProxy_Entries(t *testing.T) {
	r := &runneryml.Runner{TCPEgress: []string{"db.neon.tech:5432"}}
	out := string(RenderHAProxy(r, security.Policy{}))
	for _, want := range []string{"frontend tcp_5432", "bind :5432", "backend backend_5432", "server srv_5432 db.neon.tech:5432", "resolvers"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderHAProxy_Empty_NoListeners(t *testing.T) {
	out := string(RenderHAProxy(&runneryml.Runner{}, security.Policy{}))
	if strings.Contains(out, "frontend tcp_") {
		t.Fatalf("unexpected listener in empty config:\n%s", out)
	}
}

// Attacker: a malicious tcp_egress value containing a newline must never produce
// a live directive — the renderer must strip the entry entirely, not interpolate
// the embedded newline into the config.
func TestRenderHAProxy_InjectionInert(t *testing.T) {
	r := &runneryml.Runner{TCPEgress: []string{"evil\nacl x:5432"}}
	out := string(RenderHAProxy(r, security.Policy{}))
	if strings.Contains(out, "frontend tcp_") {
		t.Fatalf("malicious entry with embedded newline must produce NO frontend:\n%s", out)
	}
}

// Additional test: multiple TCP egress entries
func TestRenderHAProxy_MultipleEntries(t *testing.T) {
	r := &runneryml.Runner{TCPEgress: []string{"db.neon.tech:5432", "redis.example.com:6379"}}
	out := string(RenderHAProxy(r, security.Policy{}))

	require.Contains(t, out, "frontend tcp_5432")
	require.Contains(t, out, "bind :5432")
	require.Contains(t, out, "server srv_5432 db.neon.tech:5432")

	require.Contains(t, out, "frontend tcp_6379")
	require.Contains(t, out, "bind :6379")
	require.Contains(t, out, "server srv_6379 redis.example.com:6379")

	// Should have exactly 2 frontends
	require.Equal(t, 2, strings.Count(out, "frontend tcp_"))
}

// Test that invalid host:port formats are skipped (defense-in-depth)
func TestRenderHAProxy_InvalidFormat_Skipped(t *testing.T) {
	r := &runneryml.Runner{TCPEgress: []string{"nocolon", ":::::::"}}
	out := string(RenderHAProxy(r, security.Policy{}))
	// Should not produce any TCP frontends
	require.NotContains(t, out, "frontend tcp_")
}

// Test that the config has proper structure and defaults
func TestRenderHAProxy_ProperStructure(t *testing.T) {
	r := &runneryml.Runner{TCPEgress: []string{"db.example.com:5432"}}
	out := string(RenderHAProxy(r, security.Policy{}))

	require.Contains(t, out, "global")
	require.Contains(t, out, "maxconn 256")
	require.Contains(t, out, "defaults")
	require.Contains(t, out, "mode tcp")
	require.Contains(t, out, "timeout connect 10s")
	require.Contains(t, out, "timeout client 60s")
	require.Contains(t, out, "timeout server 60s")
	require.Contains(t, out, "resolvers default_dns")
	require.Contains(t, out, "parse-resolv-conf")
	require.Contains(t, out, "resolve_retries 3")
	require.Contains(t, out, "timeout retry 1s")
	require.Contains(t, out, "hold valid 10s")
}

// Test that dangerous characters are rejected (newlines, carriage returns, etc.)
func TestRenderHAProxy_DangerousChars_Rejected(t *testing.T) {
	testCases := []struct {
		name      string
		tcpEgress string
		should    string
	}{
		{"newline in host", "db\n.com:5432", "reject"},
		{"carriage return in host", "db\r.com:5432", "reject"},
		{"space in host", "db .com:5432", "reject"},
		{"hash in host", "db#.com:5432", "reject"},
		{"tab in host", "db\t.com:5432", "reject"},
		{"newline in port", "db.com:543\n2", "reject"},
		{"space in port", "db.com:543 2", "reject"},
		{"hash in port", "db.com:543#2", "reject"},
		{"tab in port", "db.com:543\t2", "reject"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &runneryml.Runner{TCPEgress: []string{tc.tcpEgress}}
			out := string(RenderHAProxy(r, security.Policy{}))
			// Should not have any frontend entries for dangerous input
			require.NotContains(t, out, "frontend tcp_", "dangerous input should be rejected")
		})
	}
}
