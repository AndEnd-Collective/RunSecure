package runneryml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	require.Equal(t, []string{"*.npmjs.org"}, r.Orchestrator.SecurityOverrides.AllowWildcards)
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
