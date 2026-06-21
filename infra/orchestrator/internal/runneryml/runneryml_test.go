package runneryml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// parseYAML is a test helper that parses YAML bytes directly.
func parseYAML(b []byte) (*Runner, error) {
	var r Runner
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Orchestrator.TimeoutSeconds <= 0 {
		r.Orchestrator.TimeoutSeconds = DefaultTimeoutSeconds
	}
	return &r, nil
}

func TestParse_AllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.yml")
	require.NoError(t, os.WriteFile(path, []byte(`
runtime: node:24
labels: [self-hosted, Linux, ARM64, container]
version: 1.2.3
resources:
  memory: 8g
  cpus: 4
  pids: 2048
egress:
  allow_domains: [registry.npmjs.org, api.github.com]
orchestrator:
  timeout_seconds: 7200
  security_overrides:
    allow_wildcards: ["*.npmjs.org"]
  seccomp_profile: node-runner.json
`), 0o644))

	r, err := Parse(path)
	require.NoError(t, err)
	require.Equal(t, "node:24", r.Runtime)
	require.Equal(t, []string{"self-hosted", "Linux", "ARM64", "container"}, r.Labels)
	require.Equal(t, "8g", r.Resources.Memory)
	require.Equal(t, 4, r.Resources.CPUs)
	require.Equal(t, 2048, r.Resources.PIDs)
	require.Equal(t, []string{"registry.npmjs.org", "api.github.com"}, r.Egress.AllowDomains)
	require.Equal(t, 7200, r.Orchestrator.TimeoutSeconds)
	require.Equal(t, []any{"*.npmjs.org"}, r.Orchestrator.SecurityOverrides["allow_wildcards"])
	require.Equal(t, "node-runner.json", r.Orchestrator.SeccompProfile)
}

func TestParse_DefaultsForOptionalOrchestratorBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.yml")
	require.NoError(t, os.WriteFile(path, []byte("runtime: node:24\n"), 0o644))

	r, err := Parse(path)
	require.NoError(t, err)
	require.Equal(t, DefaultTimeoutSeconds, r.Orchestrator.TimeoutSeconds)
}

func TestParse_FileMissing(t *testing.T) {
	_, err := Parse("/nonexistent/runner.yml")
	require.Error(t, err)
}

func TestParse_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.yml")
	require.NoError(t, os.WriteFile(path, []byte(": : : not yaml"), 0o644))
	_, err := Parse(path)
	require.Error(t, err)
}

func TestParse_TCPandHTTPEgress(t *testing.T) {
	y := []byte("runtime: node:24\nhttp_egress: [\".neon.tech\"]\ntcp_egress: [\"db.neon.tech:5432\"]\ndns:\n  host: false\n  servers: [\"10.0.0.53\"]\n")
	r, err := parseYAML(y)
	require.NoError(t, err)
	require.Equal(t, 1, len(r.TCPEgress))
	require.Equal(t, "db.neon.tech:5432", r.TCPEgress[0])
	got := r.ResolvedHTTPEgress()
	require.Equal(t, 1, len(got))
	require.Equal(t, ".neon.tech", got[0])
	require.NotNil(t, r.DNS.Host)
	require.Equal(t, false, *r.DNS.Host)
}

func TestResolvedHTTPEgress_DeprecatedAlias(t *testing.T) {
	y := []byte("runtime: node:24\negress:\n  allow_domains: [\"api.github.com\"]\n")
	r, err := parseYAML(y)
	require.NoError(t, err)
	got := r.ResolvedHTTPEgress()
	require.Equal(t, 1, len(got))
	require.Equal(t, "api.github.com", got[0])
}

func TestValidateEgress(t *testing.T) {
	cases := []struct {
		name    string
		tcp     []string
		http    []string
		wantErr bool
	}{
		{"ok-tcp-only", []string{"db:5432", "redis:6379"}, []string{}, false},
		{"ok-tcp-and-http", []string{"db:5432"}, []string{".example.com"}, false},
		{"dup-port", []string{"a:5432", "b:5432"}, []string{}, true},
		{"reserved-443", []string{"a:443"}, []string{}, true},
		{"reserved-80", []string{"a:80"}, []string{}, true},
		{"no-port", []string{"hostonly"}, []string{}, true},
		{"bad-port", []string{"a:notnum"}, []string{}, true},
		{"injection", []string{"a:5432\nacl x"}, []string{}, true},
		{"bad-domain-trailing-dash", []string{}, []string{".invalid-"}, true},
		{"bad-domain-leading-dash", []string{}, []string{"-invalid"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Runner{TCPEgress: c.tcp, HTTPEgress: c.http}
			err := r.ValidateEgress()
			if c.wantErr {
				require.Error(t, err, "expected error for case %s", c.name)
			} else {
				require.NoError(t, err, "expected no error for case %s", c.name)
			}
		})
	}
}
